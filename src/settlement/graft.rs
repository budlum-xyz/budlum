//! WIRING: verify_graft_payment has no in-tree caller by design: bud_getGraftPayment returns the proof to the caller, who verifies it against their own trust anchor (documented in rpc/api.rs).
//! WIRING: wired - registration, ownership claims, payments, solver intents,
//! bids, fulfilment and refunds run in block through `SettlementTx::Graft`;
//! the Ethereum-side `GraftExecutor` contract is ().
//!
//! Graft: an application that lives on another network is used from
//! Budlum and paid for in BUD, without moving there.
//!
//! A Graft row binds an application on an origin domain to one deterministic,
//! keyless Budlum mirror account. Nothing leaves the mirror except by a rule
//! of this module; there is no administrator key.
//!
//! - **Register** is permissionless and idempotent. It names no owner: the
//!   registrant gains nothing over the application.
//! - **Claim** proves, from the origin domain, that the application itself
//!   names a Budlum payout address: an anchored `budlum/graft/claim/v1`
//!   event emitted by the application. The payout becomes the owner and the
//!   mirror balance moves to it. A later claim event rotates the owner.
//! - **Pay** moves BUD from a user to the application: to its owner, or into
//!   the mirror while nobody has claimed it.
//! - **OpenIntent / Bid / Fulfill / Refund** let a user ask a solver to make
//!   a call on the origin chain, paid in BUD. The user's maximum payment is
//!   escrowed; only an active RELAYER bids; a solver is paid when an anchored
//!   `budlum/graft/fulfilled/v1` event from the domain's executor proves this
//!   exact call for this exact intent; an expired intent refunds the user and
//!   slashes every bidder that did not deliver.
//!
//! External evidence uses the anchored-result model of the bridge and the
//! relayer intents ([`crate::relayer::policy::verify_anchored_result`]): a
//! cross-domain message whose result leaf reaches the root consensus has
//! anchored for that domain.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::core::transaction::RelayerExternalResult;
use crate::cross_domain::message::MessageKind;
use crate::settlement::domains::{SettlementTxContext, SettlementTxError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Event kind an origin application emits to name its Budlum payout.
pub const GRAFT_CLAIM_KIND: &[u8] = b"budlum/graft/claim/v1";
/// Event kind a domain's Graft executor emits after carrying out a call.
pub const GRAFT_FULFILLED_KIND: &[u8] = b"budlum/graft/fulfilled/v1";
/// Upper bound of an origin application, executor or recipient identifier.
pub const MAX_GRAFT_IDENTIFIER_BYTES: usize = 256;
/// Registered applications held in state.
pub const MAX_GRAFT_APPS: usize = 10_000;
/// Recent payments held in state for payment proofs; older rows leave the
/// window (an indexer keeps the history).
pub const GRAFT_PAYMENT_WINDOW: usize = 10_000;
/// Open intents held in state.
pub const MAX_GRAFT_OPEN_INTENTS: usize = 10_000;
/// Bids one intent may hold.
pub const MAX_GRAFT_BIDS_PER_INTENT: usize = 16;
/// Claim messages remembered for replay protection.
pub const MAX_GRAFT_USED_MESSAGES: usize = 100_000;
/// The farthest deadline an intent may name, in blocks from now.
pub const MAX_GRAFT_INTENT_HORIZON_BLOCKS: u64 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GraftStatus {
    #[default]
    Active,
    Paused,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraftApp {
    pub graft_id: [u8; 32],
    /// The claimed owner; zero until a claim proves one.
    pub owner: Address,
    pub domain_key: u32,
    pub origin_app: Vec<u8>,
    /// B.U.D. content id of the application's metadata.
    pub manifest_hash: [u8; 32],
    pub mirror_account: Address,
    pub status: GraftStatus,
    pub registered_at_block: u64,
}

impl GraftApp {
    /// Where this application's payments and fee share land: the claimed
    /// owner, or the keyless mirror account while nobody has claimed it.
    #[must_use]
    pub fn fee_recipient(&self) -> Address {
        if self.owner == Address::zero() {
            self.mirror_account
        } else {
            self.owner
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraftPayment {
    pub payment_id: [u8; 32],
    pub graft_id: [u8; 32],
    pub payer: Address,
    pub recipient: Address,
    pub amount: u64,
    pub origin_recipient: Vec<u8>,
    pub memo_hash: [u8; 32],
    pub paid_at_block: u64,
}

impl GraftPayment {
    /// The leaf a payment proof opens.
    #[must_use]
    pub fn leaf_hash(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_GRAFT_PAYMENT_LEAF_V1",
            &self.payment_id,
            &self.graft_id,
            self.payer.as_bytes(),
            self.recipient.as_bytes(),
            &self.amount.to_le_bytes(),
            &u64::try_from(self.origin_recipient.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
            &self.origin_recipient,
            &self.memo_hash,
            &self.paid_at_block.to_le_bytes(),
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraftBid {
    pub solver: Address,
    /// What the solver spends on the origin chain, in BUD.
    pub cost: u64,
    /// The solver's fee, at most the intent's cap.
    pub fee: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraftIntent {
    pub intent_id: [u8; 32],
    pub graft_id: [u8; 32],
    pub owner: Address,
    /// Hash of the call data the solver must make on the origin chain.
    pub call_hash: [u8; 32],
    /// Origin-chain value the call carries, in the origin chain's unit.
    pub value: u64,
    /// The escrowed BUD: solver cost, solver fee and service price come
    /// out of it, the rest returns to the owner.
    pub max_payment: u64,
    pub solver_fee_cap: u64,
    /// The application's price for the service, paid on fulfilment.
    pub service_price: u64,
    pub origin_beneficiary: Vec<u8>,
    pub deadline_block: u64,
    pub bids: Vec<GraftBid>,
}

/// State-rooted Graft writes. Every variant is carried by a signed settlement
/// transaction, so the sender is `ctx.sender`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GraftTx {
    /// Register an origin application. Permissionless, idempotent.
    Register {
        domain_key: u32,
        origin_app: Vec<u8>,
        manifest_hash: [u8; 32],
    },
    /// Prove the application names `payout` as its Budlum owner.
    Claim {
        graft_id: [u8; 32],
        payout: Address,
        evidence: Box<RelayerExternalResult>,
    },
    /// Pay the application in BUD.
    Pay {
        graft_id: [u8; 32],
        amount: u64,
        memo_hash: [u8; 32],
        origin_recipient: Vec<u8>,
    },
    /// Pause, resume or retire the application (owner only; retiring is
    /// final).
    SetStatus {
        graft_id: [u8; 32],
        status: GraftStatus,
    },
    /// Name the Graft executor contract of a domain (that domain's operator
    /// only). Fulfilment events count only from this emitter.
    SetExecutor { domain_key: u32, executor: Vec<u8> },
    /// Ask a solver to make a call on the origin chain; escrow the maximum.
    OpenIntent {
        graft_id: [u8; 32],
        call_hash: [u8; 32],
        value: u64,
        max_payment: u64,
        solver_fee_cap: u64,
        service_price: u64,
        origin_beneficiary: Vec<u8>,
        /// Zero takes the genesis default.
        deadline_block: u64,
    },
    /// Offer to carry out an intent (active RELAYER only).
    Bid {
        intent_id: [u8; 32],
        cost: u64,
        fee: u64,
    },
    /// Prove the call was made and collect the bid.
    Fulfill {
        intent_id: [u8; 32],
        evidence: Box<RelayerExternalResult>,
    },
    /// Refund an expired intent and slash its undelivered bidders.
    Refund { intent_id: [u8; 32] },
    /// Prove the payout with the application's own key when the application
    /// is an externally owned account (8.2 (b)): an EIP-191
    /// personal-sign signature over [`eoa_claim_hash`]. The signature expires
    /// at `valid_until_block`, so an old signature cannot undo a later
    /// rotation once the window is over, and each one works once.
    ClaimBySignature {
        graft_id: [u8; 32],
        payout: Address,
        valid_until_block: u64,
        signature: Vec<u8>,
    },
}

/// The 32-byte message an externally owned application signs (EIP-191
/// personal sign) to name its Budlum payout.
#[must_use]
pub fn eoa_claim_hash(
    chain_id: u64,
    graft_id: [u8; 32],
    payout: Address,
    valid_until_block: u64,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_GRAFT_EOA_CLAIM_V1",
        &chain_id.to_le_bytes(),
        &graft_id,
        payout.as_bytes(),
        &valid_until_block.to_le_bytes(),
    ])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraftRegistry {
    #[serde(with = "crate::core::map_keys")]
    pub apps: BTreeMap<[u8; 32], GraftApp>,
    /// The most recent payments, oldest first.
    pub payments: Vec<GraftPayment>,
    pub payment_count: u64,
    #[serde(with = "crate::core::map_keys")]
    pub intents: BTreeMap<[u8; 32], GraftIntent>,
    pub intent_count: u64,
    /// The Graft executor of each domain, set by the domain's operator.
    pub executors: BTreeMap<u32, Vec<u8>>,
    /// Claim message ids already used: an anchored claim works once.
    pub used_messages: BTreeSet<[u8; 32]>,
}

/// What a payment proof needs besides the payment's own Merkle path: the
/// other half of the registry root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraftRootOpening {
    pub payments_root: [u8; 32],
    pub rest_hash: [u8; 32],
}

impl GraftRootOpening {
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_GRAFT_REGISTRY_V2",
            &self.payments_root,
            &self.rest_hash,
        ])
    }
}

/// The Merkle root of a payment window.
#[must_use]
pub fn window_root(payments: &[GraftPayment]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = payments.iter().map(GraftPayment::leaf_hash).collect();
    crate::settlement::commitment_tree::merkle_root(&leaves)
}

/// A payment of `payments` with its Merkle path to [`window_root`].
#[must_use]
pub fn window_proof(
    payments: &[GraftPayment],
    payment_id: &[u8; 32],
) -> Option<(GraftPayment, crate::cross_domain::event_tree::MerkleProof)> {
    let index = payments
        .iter()
        .position(|payment| &payment.payment_id == payment_id)?;
    let leaves: Vec<[u8; 32]> = payments.iter().map(GraftPayment::leaf_hash).collect();
    let siblings = crate::consensus::merkle_tree::merkle_proof(
        &leaves,
        index,
        crate::settlement::commitment_tree::merkle_node_hash,
        crate::settlement::commitment_tree::merkle_odd_promote_hash,
    )?;
    Some((
        payments.get(index)?.clone(),
        crate::cross_domain::event_tree::MerkleProof {
            leaf: *leaves.get(index)?,
            index,
            siblings,
        },
    ))
}

/// Everything an application needs to check a Graft payment itself
///: the payment, its path to the payment window root, the
/// other half of the registry root, and the checkpoint header that commits
/// that root with the material that ties the header to a finalized block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraftPaymentProof {
    pub payment: GraftPayment,
    pub path: crate::cross_domain::event_tree::MerkleProof,
    pub opening: GraftRootOpening,
    pub header: crate::settlement::GlobalBlockHeader,
    pub block_height: u64,
    pub state_root: String,
    pub state_root_body: Option<[u8; 32]>,
}

/// Why a Graft payment proof does not hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GraftProofError {
    #[error("the payment does not hash to the proven leaf")]
    Leaf,
    #[error("the payment path does not reach the window root")]
    Path,
    #[error("the registry opening does not reproduce the header's Graft root")]
    Opening,
    #[error("the proof carries no state root opening for its checkpoint")]
    NoStateRootBody,
    #[error("the header is not the one the finalized checkpoint commits: {0}")]
    Header(String),
}

/// Check a Graft payment proof against a finalized checkpoint the caller
/// already trusts (a [`crate::light_client::VerifiedCheckpoint`] reached
/// from its trust anchor). The chain checked is: finalized checkpoint ->
/// state root -> global header -> Graft root -> payment window -> payment.
///
/// # Errors
///
/// The first link that does not hold.
pub fn verify_graft_payment(
    proof: &GraftPaymentProof,
    checkpoint: &crate::light_client::VerifiedCheckpoint,
) -> Result<(), GraftProofError> {
    if proof.path.leaf != proof.payment.leaf_hash() {
        return Err(GraftProofError::Leaf);
    }
    if !proof.path.verify(proof.opening.payments_root) {
        return Err(GraftProofError::Path);
    }
    if proof.header.graft_root != Some(proof.opening.root()) {
        return Err(GraftProofError::Opening);
    }
    let body = proof
        .state_root_body
        .ok_or(GraftProofError::NoStateRootBody)?;
    crate::light_client::LightClient::verify_global_header(checkpoint, &body, &proof.header)
        .map_err(|e| GraftProofError::Header(e.to_string()))
}

/// `H("BDLM_GRAFT_APP_V1", domain_key, origin_app)`.
#[must_use]
pub fn graft_id(domain_key: u32, origin_app: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_GRAFT_APP_V1",
        &domain_key.to_le_bytes(),
        &u64::try_from(origin_app.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
        origin_app,
    ])
}

/// `H("BDLM_GRAFT_MIRROR_V1", graft_id)`: an address no key controls.
#[must_use]
pub fn mirror_account(graft_id: [u8; 32]) -> Address {
    Address::from(hash_fields_bytes(&[b"BDLM_GRAFT_MIRROR_V1", &graft_id]))
}

/// The Budlum address an origin identifier emits events as. An identifier
/// of up to 32 bytes (an EVM address is 20) is right-aligned in a zeroed
/// word, the way an EVM word holds an address; a longer one is hashed.
#[must_use]
pub fn origin_emitter(origin: &[u8]) -> Address {
    if origin.len() <= 32 {
        let mut word = [0u8; 32];
        word[32 - origin.len()..].copy_from_slice(origin);
        Address::from(word)
    } else {
        Address::from(hash_fields_bytes(&[
            b"BDLM_GRAFT_ORIGIN_EMITTER_V1",
            origin,
        ]))
    }
}

/// The payload hash of the claim event an application emits.
#[must_use]
pub fn claim_payload_hash(graft_id: [u8; 32], payout: Address) -> [u8; 32] {
    hash_fields_bytes(&[b"BDLM_GRAFT_CLAIM_EVENT_V1", &graft_id, payout.as_bytes()])
}

/// The payload hash of the fulfilment event the executor emits: the intent,
/// the target, the call, the value, the beneficiary and the solver.
#[must_use]
pub fn fulfilled_payload_hash(
    intent: &GraftIntent,
    origin_app: &[u8],
    solver: Address,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_GRAFT_FULFILLED_EVENT_V1",
        &intent.intent_id,
        &u64::try_from(origin_app.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
        origin_app,
        &intent.call_hash,
        &intent.value.to_le_bytes(),
        &u64::try_from(intent.origin_beneficiary.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
        &intent.origin_beneficiary,
        solver.as_bytes(),
    ])
}

fn identifier_ok(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len() <= MAX_GRAFT_IDENTIFIER_BYTES
}

fn encoded(value: &impl Serialize) -> Vec<u8> {
    bincode::serialize(value).unwrap_or_else(|_| b"BDLM_GRAFT_UNENCODABLE_V1".to_vec())
}

impl GraftRegistry {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.apps.is_empty()
            && self.payments.is_empty()
            && self.payment_count == 0
            && self.intents.is_empty()
            && self.intent_count == 0
            && self.executors.is_empty()
            && self.used_messages.is_empty()
    }

    /// The Merkle root of the payment window.
    #[must_use]
    pub fn payments_root(&self) -> [u8; 32] {
        window_root(&self.payments)
    }

    /// The two halves the registry root folds.
    #[must_use]
    pub fn opening(&self) -> GraftRootOpening {
        let rest_hash = hash_fields_bytes(&[
            b"BDLM_GRAFT_REST_V1",
            &encoded(&self.apps),
            &self.payment_count.to_le_bytes(),
            &encoded(&self.intents),
            &self.intent_count.to_le_bytes(),
            &encoded(&self.executors),
            &encoded(&self.used_messages),
        ]);
        GraftRootOpening {
            payments_root: self.payments_root(),
            rest_hash,
        }
    }

    /// The registry root: the state root and the global header commit it.
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.opening().root()
    }

    #[must_use]
    pub fn get(&self, graft_id: &[u8; 32]) -> Option<&GraftApp> {
        self.apps.get(graft_id)
    }

    /// The application whose mirror account is `mirror`, if any.
    #[must_use]
    pub fn by_mirror(&self, mirror: &Address) -> Option<&GraftApp> {
        self.apps.values().find(|app| &app.mirror_account == mirror)
    }

    /// A payment still in the window, with its Merkle path to
    /// [`Self::payments_root`].
    #[must_use]
    /// WIRING: unwired - no caller in this tree yet; kept as the surface its wave wires up, and nothing depends on it until then.
    pub fn payment_proof(
        &self,
        payment_id: &[u8; 32],
    ) -> Option<(GraftPayment, crate::cross_domain::event_tree::MerkleProof)> {
        window_proof(&self.payments, payment_id)
    }

    /// BUD escrowed by open intents: counted in the supply, held by no
    /// account.
    #[must_use]
    pub fn total_escrowed_supply(&self) -> u128 {
        self.intents.values().fold(0u128, |total, intent| {
            total.saturating_add(u128::from(intent.max_payment))
        })
    }

    /// Register an application. `Ok(true)` when a row was written,
    /// `Ok(false)` when the identical application was already registered.
    pub fn register(
        &mut self,
        domain_key: u32,
        origin_app: Vec<u8>,
        manifest_hash: [u8; 32],
        block: u64,
    ) -> Result<bool, String> {
        if !identifier_ok(&origin_app) {
            return Err("Graft origin_app length is invalid".into());
        }
        if manifest_hash == [0u8; 32] {
            return Err("Graft manifest_hash cannot be zero".into());
        }
        let id = graft_id(domain_key, &origin_app);
        if let Some(existing) = self.apps.get(&id) {
            if existing.manifest_hash == manifest_hash {
                return Ok(false);
            }
            return Err("Graft application is already registered with another manifest".into());
        }
        if self.apps.len() >= MAX_GRAFT_APPS {
            return Err("Graft application registry is full".into());
        }
        self.apps.insert(
            id,
            GraftApp {
                graft_id: id,
                owner: Address::zero(),
                domain_key,
                origin_app,
                manifest_hash,
                mirror_account: mirror_account(id),
                status: GraftStatus::Active,
                registered_at_block: block,
            },
        );
        Ok(true)
    }

    fn record_payment(&mut self, mut payment: GraftPayment) -> [u8; 32] {
        payment.payment_id = hash_fields_bytes(&[
            b"BDLM_GRAFT_PAYMENT_V1",
            &payment.graft_id,
            payment.payer.as_bytes(),
            &self.payment_count.to_le_bytes(),
        ]);
        self.payment_count = self.payment_count.saturating_add(1);
        let id = payment.payment_id;
        self.payments.push(payment);
        if self.payments.len() > GRAFT_PAYMENT_WINDOW {
            let excess = self.payments.len() - GRAFT_PAYMENT_WINDOW;
            self.payments.drain(..excess);
        }
        id
    }
}

/// The account that receives the application share of `tx`'s protocol fee.
///
/// Only a registered, active Graft application earns a share, and the
/// application is identified from the transaction's own effect: the Graft id
/// of a payment or an intent, or the mirror account a contract call names.
/// A share never returns to the sender itself, so a sender cannot discount
/// its own fee by naming its own application.
#[must_use]
pub fn application_fee_recipient(
    state: &AccountState,
    tx: &crate::core::transaction::Transaction,
) -> Option<Address> {
    use crate::core::transaction::TransactionType;
    use crate::settlement::domains::SettlementTx;
    let registry = &state.settlement.graft;
    let app = match &tx.tx_type {
        TransactionType::ContractCall if tx.to != Address::zero() => registry.by_mirror(&tx.to),
        TransactionType::Settlement(SettlementTx::Graft(graft_tx)) => match graft_tx.as_ref() {
            GraftTx::Pay { graft_id, .. } | GraftTx::OpenIntent { graft_id, .. } => {
                registry.get(graft_id)
            }
            _ => None,
        },
        _ => None,
    }?;
    if app.status != GraftStatus::Active {
        return None;
    }
    let recipient = app.fee_recipient();
    (recipient != tx.from).then_some(recipient)
}

fn refused(reason: impl Into<String>) -> SettlementTxError {
    SettlementTxError::Refused(reason.into())
}

/// Record `payout` as the owner of `app` (each proof works once, keyed by
/// `proof_id`) and move what accrued in the mirror account to it.
fn apply_claim(
    state: &mut AccountState,
    app: &GraftApp,
    graft_id: &[u8; 32],
    payout: Address,
    proof_id: [u8; 32],
) -> Result<(), SettlementTxError> {
    let registry = &mut state.settlement.graft;
    if registry.used_messages.contains(&proof_id) {
        return Err(refused("Graft claim proof has already been used"));
    }
    if registry.used_messages.len() >= MAX_GRAFT_USED_MESSAGES {
        return Err(refused("Graft claim replay set is full"));
    }
    registry.used_messages.insert(proof_id);
    if let Some(row) = registry.apps.get_mut(graft_id) {
        row.owner = payout;
    }
    // Everything that accrued while nobody owned the application moves to
    // its owner now.
    let swept = state.get_balance(&app.mirror_account);
    if swept > 0 {
        state
            .get_balance(&payout)
            .checked_add(swept)
            .ok_or_else(|| refused("Graft payout would overflow"))?;
        let mirror = state.get_or_create(&app.mirror_account);
        mirror.balance = 0;
        state.mark_dirty(&app.mirror_account);
        credit(state, &payout, swept)?;
    }
    Ok(())
}

/// Move `amount` out of the sender's spendable balance, keeping `fee` for
/// the executor to take after the door.
fn debit(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    amount: u64,
) -> Result<(), SettlementTxError> {
    let needed = amount
        .checked_add(ctx.fee)
        .ok_or_else(|| refused("Graft amount overflows"))?;
    let balance = state.spendable_balance(&ctx.sender);
    if balance < needed {
        return Err(SettlementTxError::BondUnfunded { needed, balance });
    }
    let account = state.get_or_create(&ctx.sender);
    account.balance = account
        .balance
        .checked_sub(amount)
        .ok_or_else(|| refused("Graft debit underflow"))?;
    state.mark_dirty(&ctx.sender);
    Ok(())
}

fn credit(state: &mut AccountState, to: &Address, amount: u64) -> Result<(), SettlementTxError> {
    if amount == 0 {
        return Ok(());
    }
    state
        .try_add_balance(to, amount)
        .map_err(SettlementTxError::Refused)
}

/// Execute one Graft transaction through the settlement door.
pub fn execute_graft_tx(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    tx: &GraftTx,
) -> Result<(), SettlementTxError> {
    let block = state.current_block_height;
    match tx {
        GraftTx::Register {
            domain_key,
            origin_app,
            manifest_hash,
        } => {
            if state.settlement.domains.get(*domain_key).is_none() {
                return Err(refused("Graft domain_key is not a registered domain"));
            }
            let registration_fee = state.registry.params().graft_registration_fee;
            let funded = state
                .spendable_balance(&ctx.sender)
                .checked_sub(ctx.fee)
                .is_some_and(|left| left >= registration_fee);
            if !funded {
                return Err(SettlementTxError::BondUnfunded {
                    needed: ctx.fee.saturating_add(registration_fee),
                    balance: state.spendable_balance(&ctx.sender),
                });
            }
            let written = state
                .settlement
                .graft
                .register(*domain_key, origin_app.clone(), *manifest_hash, block)
                .map_err(SettlementTxError::Refused)?;
            if written {
                // The registration fee is destroyed, and recorded as such
                // so it does not reopen mint headroom under the cap.
                debit(state, ctx, registration_fee)?;
                state.burned_total = state.burned_total.saturating_add(registration_fee);
            }
            Ok(())
        }
        GraftTx::Claim {
            graft_id,
            payout,
            evidence,
        } => {
            if *payout == Address::zero() {
                return Err(refused("Graft payout cannot be zero"));
            }
            let app = state
                .settlement
                .graft
                .get(graft_id)
                .cloned()
                .ok_or_else(|| refused("Graft application not found"))?;
            if app.status == GraftStatus::Retired {
                return Err(refused("a retired Graft application cannot be claimed"));
            }
            if evidence.chain.domain_id() != app.domain_key {
                return Err(refused("Graft claim evidence comes from another domain"));
            }
            let message =
                crate::relayer::policy::verify_anchored_result(&state.external_roots, evidence)
                    .map_err(SettlementTxError::Refused)?;
            if message.kind != MessageKind::Custom(GRAFT_CLAIM_KIND.to_vec())
                || message.correlation_id != Some(*graft_id)
                || message.sender != origin_emitter(&app.origin_app)
                || message.recipient != *payout
                || message.payload_hash != claim_payload_hash(*graft_id, *payout)
            {
                return Err(refused(
                    "Graft claim event does not bind the application and the payout",
                ));
            }
            let message_id = message.message_id;
            apply_claim(state, &app, graft_id, *payout, message_id)
        }
        GraftTx::ClaimBySignature {
            graft_id,
            payout,
            valid_until_block,
            signature,
        } => {
            if *payout == Address::zero() {
                return Err(refused("Graft payout cannot be zero"));
            }
            if block > *valid_until_block {
                return Err(refused("the Graft claim signature has expired"));
            }
            if *valid_until_block > block.saturating_add(MAX_GRAFT_INTENT_HORIZON_BLOCKS) {
                return Err(refused("the Graft claim signature is valid too far ahead"));
            }
            let app = state
                .settlement
                .graft
                .get(graft_id)
                .cloned()
                .ok_or_else(|| refused("Graft application not found"))?;
            if app.status == GraftStatus::Retired {
                return Err(refused("a retired Graft application cannot be claimed"));
            }
            let eoa: [u8; 20] = app
                .origin_app
                .as_slice()
                .try_into()
                .map_err(|_| refused("only a 20-byte account can claim by signature"))?;
            let digest = crate::crypto::secp256k1_recover::eip191_digest(&eoa_claim_hash(
                ctx.chain_id,
                *graft_id,
                *payout,
                *valid_until_block,
            ));
            let signer = crate::crypto::secp256k1_recover::recover_address(&digest, signature)
                .map_err(|e| refused(e.to_string()))?;
            if signer != eoa {
                return Err(refused(
                    "the Graft claim signature is not the application's key",
                ));
            }
            apply_claim(state, &app, graft_id, *payout, digest)
        }
        GraftTx::Pay {
            graft_id,
            amount,
            memo_hash,
            origin_recipient,
        } => {
            if *amount == 0 {
                return Err(refused("Graft payment amount must be non-zero"));
            }
            if !identifier_ok(origin_recipient) {
                return Err(refused("Graft origin_recipient length is invalid"));
            }
            let app = state
                .settlement
                .graft
                .get(graft_id)
                .cloned()
                .ok_or_else(|| refused("Graft application not found"))?;
            if app.status != GraftStatus::Active {
                return Err(refused("Graft application is not active"));
            }
            let recipient = app.fee_recipient();
            if state.get_balance(&recipient).checked_add(*amount).is_none() {
                return Err(refused("Graft payment would overflow the recipient"));
            }
            debit(state, ctx, *amount)?;
            credit(state, &recipient, *amount)?;
            state.settlement.graft.record_payment(GraftPayment {
                payment_id: [0u8; 32],
                graft_id: *graft_id,
                payer: ctx.sender,
                recipient,
                amount: *amount,
                origin_recipient: origin_recipient.clone(),
                memo_hash: *memo_hash,
                paid_at_block: block,
            });
            Ok(())
        }
        GraftTx::SetStatus { graft_id, status } => {
            let app = state
                .settlement
                .graft
                .apps
                .get_mut(graft_id)
                .ok_or_else(|| refused("Graft application not found"))?;
            if app.owner == Address::zero() || app.owner != ctx.sender {
                return Err(refused(
                    "only the claimed Graft owner may change its status",
                ));
            }
            if app.status == GraftStatus::Retired {
                return Err(refused("a retired Graft application stays retired"));
            }
            app.status = *status;
            Ok(())
        }
        GraftTx::SetExecutor {
            domain_key,
            executor,
        } => {
            let operator = state
                .settlement
                .domains
                .get(*domain_key)
                .ok_or_else(|| refused("Graft executor names an unregistered domain"))?
                .operator;
            if operator != Some(ctx.sender) {
                return Err(refused(
                    "only the domain operator may name its Graft executor",
                ));
            }
            if !identifier_ok(executor) {
                return Err(refused("Graft executor length is invalid"));
            }
            state
                .settlement
                .graft
                .executors
                .insert(*domain_key, executor.clone());
            Ok(())
        }
        GraftTx::OpenIntent {
            graft_id,
            call_hash,
            value,
            max_payment,
            solver_fee_cap,
            service_price,
            origin_beneficiary,
            deadline_block,
        } => {
            let app = state
                .settlement
                .graft
                .get(graft_id)
                .cloned()
                .ok_or_else(|| refused("Graft application not found"))?;
            if app.status != GraftStatus::Active {
                return Err(refused("Graft application is not active"));
            }
            if !state
                .settlement
                .graft
                .executors
                .contains_key(&app.domain_key)
            {
                return Err(refused("the Graft application's domain has no executor"));
            }
            if *call_hash == [0u8; 32] {
                return Err(refused("Graft call_hash cannot be zero"));
            }
            if !identifier_ok(origin_beneficiary) {
                return Err(refused("Graft origin_beneficiary length is invalid"));
            }
            let reserved = solver_fee_cap
                .checked_add(*service_price)
                .ok_or_else(|| refused("Graft intent prices overflow"))?;
            if *max_payment == 0 || reserved > *max_payment {
                return Err(refused(
                    "Graft max_payment must cover the solver fee cap and the service price",
                ));
            }
            let deadline = if *deadline_block == 0 {
                block.saturating_add(state.registry.params().graft_default_intent_deadline_blocks)
            } else {
                *deadline_block
            };
            if deadline <= block || deadline > block.saturating_add(MAX_GRAFT_INTENT_HORIZON_BLOCKS)
            {
                return Err(refused("Graft intent deadline is out of range"));
            }
            if state.settlement.graft.intents.len() >= MAX_GRAFT_OPEN_INTENTS {
                return Err(refused("Graft intent registry is full"));
            }
            debit(state, ctx, *max_payment)?;
            let registry = &mut state.settlement.graft;
            let intent_id = hash_fields_bytes(&[
                b"BDLM_GRAFT_INTENT_V1",
                graft_id,
                ctx.sender.as_bytes(),
                call_hash,
                &registry.intent_count.to_le_bytes(),
            ]);
            registry.intent_count = registry.intent_count.saturating_add(1);
            registry.intents.insert(
                intent_id,
                GraftIntent {
                    intent_id,
                    graft_id: *graft_id,
                    owner: ctx.sender,
                    call_hash: *call_hash,
                    value: *value,
                    max_payment: *max_payment,
                    solver_fee_cap: *solver_fee_cap,
                    service_price: *service_price,
                    origin_beneficiary: origin_beneficiary.clone(),
                    deadline_block: deadline,
                    bids: Vec::new(),
                },
            );
            Ok(())
        }
        GraftTx::Bid {
            intent_id,
            cost,
            fee,
        } => {
            if !state
                .registry
                .is_active(&ctx.sender, crate::registry::role::roles::RELAYER)
            {
                return Err(refused("a Graft bid requires an active RELAYER bond"));
            }
            let intent = state
                .settlement
                .graft
                .intents
                .get_mut(intent_id)
                .ok_or_else(|| refused("Graft intent not found"))?;
            if block > intent.deadline_block {
                return Err(refused("Graft intent has expired"));
            }
            let total = cost
                .checked_add(*fee)
                .and_then(|sum| sum.checked_add(intent.service_price))
                .ok_or_else(|| refused("Graft bid overflows"))?;
            if *fee > intent.solver_fee_cap || total > intent.max_payment {
                return Err(refused("Graft bid exceeds the intent's fee cap or payment"));
            }
            if intent.bids.iter().any(|bid| bid.solver == ctx.sender) {
                return Err(refused("this solver has already bid on the intent"));
            }
            if intent.bids.len() >= MAX_GRAFT_BIDS_PER_INTENT {
                return Err(refused("Graft intent bid limit reached"));
            }
            intent.bids.push(GraftBid {
                solver: ctx.sender,
                cost: *cost,
                fee: *fee,
            });
            Ok(())
        }
        GraftTx::Fulfill {
            intent_id,
            evidence,
        } => {
            let intent = state
                .settlement
                .graft
                .intents
                .get(intent_id)
                .cloned()
                .ok_or_else(|| refused("Graft intent not found"))?;
            let bid = intent
                .bids
                .iter()
                .find(|bid| bid.solver == ctx.sender)
                .cloned()
                .ok_or_else(|| refused("the sender has no bid on this Graft intent"))?;
            let app = state
                .settlement
                .graft
                .get(&intent.graft_id)
                .cloned()
                .ok_or_else(|| refused("Graft application not found"))?;
            let executor = state
                .settlement
                .graft
                .executors
                .get(&app.domain_key)
                .cloned()
                .ok_or_else(|| refused("the Graft application's domain has no executor"))?;
            if evidence.chain.domain_id() != app.domain_key {
                return Err(refused(
                    "Graft fulfilment evidence comes from another domain",
                ));
            }
            let message =
                crate::relayer::policy::verify_anchored_result(&state.external_roots, evidence)
                    .map_err(SettlementTxError::Refused)?;
            if message.kind != MessageKind::Custom(GRAFT_FULFILLED_KIND.to_vec())
                || message.correlation_id != Some(*intent_id)
                || message.sender != origin_emitter(&executor)
                || message.payload_hash
                    != fulfilled_payload_hash(&intent, &app.origin_app, ctx.sender)
            {
                return Err(refused(
                    "Graft fulfilment event does not prove this call for this intent",
                ));
            }
            let solver_paid = bid
                .cost
                .checked_add(bid.fee)
                .ok_or_else(|| refused("Graft bid overflows"))?;
            let refund = intent
                .max_payment
                .checked_sub(solver_paid)
                .and_then(|left| left.checked_sub(intent.service_price))
                .ok_or_else(|| refused("Graft escrow does not cover the bid"))?;
            let recipient = app.fee_recipient();
            state.settlement.graft.intents.remove(intent_id);
            credit(state, &ctx.sender, solver_paid)?;
            credit(state, &recipient, intent.service_price)?;
            credit(state, &intent.owner, refund)?;
            Ok(())
        }
        GraftTx::Refund { intent_id } => {
            let intent = state
                .settlement
                .graft
                .intents
                .get(intent_id)
                .cloned()
                .ok_or_else(|| refused("Graft intent not found"))?;
            if block <= intent.deadline_block {
                return Err(refused("Graft intent has not expired"));
            }
            state.settlement.graft.intents.remove(intent_id);
            // A solver that bid and did not deliver answers for it with its
            // RELAYER bond, at the liveness rate: it held the job open.
            let ratio = state.registry.params().liveness_slash_ratio_fixed;
            for bid in &intent.bids {
                let slashable = state
                    .registry
                    .get(&bid.solver, crate::registry::role::roles::RELAYER)
                    .is_some_and(crate::registry::permissionless::Registration::is_slashable);
                if slashable {
                    state
                        .slash_role_destroying(
                            bid.solver,
                            crate::registry::role::roles::RELAYER,
                            crate::registry::permissionless::SlashingCondition::LivenessFault,
                            ratio,
                        )
                        .map_err(|e| refused(e.to_string()))?;
                }
            }
            credit(state, &intent.owner, intent.max_payment)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::message::{CrossDomainMessage, CrossDomainMessageParams};

    const DOMAIN: u32 = 9;
    const FEE: u64 = 5;

    fn ctx(sender: Address) -> SettlementTxContext {
        SettlementTxContext {
            sender,
            chain_id: crate::core::transaction::DEFAULT_CHAIN_ID,
            fee: FEE,
            bls: crate::cross_domain::external::IntakeState::production_bls,
        }
    }

    fn state_with_domain(operator: Address) -> AccountState {
        let mut state = AccountState::new();
        let mut domain = crate::domain::plugin::default_domain(
            DOMAIN,
            crate::domain::ConsensusKind::PoW,
            45262,
            crate::domain::POW_HEADER_CHAIN_ADAPTER,
            1,
        );
        domain.operator = Some(operator);
        state.add_balance(&operator, domain.operator_bond.saturating_add(FEE));
        crate::settlement::domains::register_domain(&mut state, domain).unwrap();
        state
    }

    /// A one-leaf anchored result carrying `message`.
    fn anchored(
        state: &mut AccountState,
        message: CrossDomainMessage,
    ) -> Box<RelayerExternalResult> {
        let mut result = RelayerExternalResult {
            chain: crate::core::transaction::ExternalChain::Custom(DOMAIN),
            tx_hash: "0x01".into(),
            success: true,
            message: Some(message),
            receipt_proof: Vec::new(),
            external_state_root: [0u8; 32],
        };
        let leaf = result.result_leaf();
        result.receipt_proof = bincode::serialize(&crate::cross_domain::event_tree::MerkleProof {
            leaf,
            index: 0,
            siblings: Vec::new(),
        })
        .unwrap();
        result.external_state_root = leaf;
        assert!(state.anchor_external_root(DOMAIN, leaf));
        Box::new(result)
    }

    fn message(
        sender: Address,
        recipient: Address,
        payload_hash: [u8; 32],
        kind: &[u8],
        correlation: [u8; 32],
    ) -> CrossDomainMessage {
        CrossDomainMessage::new_correlated(
            CrossDomainMessageParams {
                source_domain: DOMAIN,
                target_domain: 1,
                source_height: 3,
                event_index: 0,
                nonce: 0,
                sender,
                recipient,
                payload_hash,
                kind: MessageKind::Custom(kind.to_vec()),
                expiry_height: 0,
            },
            correlation,
        )
    }

    #[test]
    fn ids_and_mirror_accounts_are_deterministic_and_keyless() {
        let id = graft_id(7, b"app");
        assert_eq!(id, graft_id(7, b"app"));
        assert_ne!(id, graft_id(8, b"app"));
        assert_ne!(mirror_account(id), Address::zero());
        assert_eq!(origin_emitter(&[0xAB; 20]).as_bytes()[12..], [0xAB; 20]);
        assert_eq!(origin_emitter(&[0xAB; 20]).as_bytes()[..12], [0u8; 12]);
    }

    #[test]
    fn registration_is_permissionless_idempotent_and_ownerless() {
        let operator = Address::from([0x01; 32]);
        let registrant = Address::from([0x02; 32]);
        let mut state = state_with_domain(operator);
        state.add_balance(&registrant, 100);
        let register = GraftTx::Register {
            domain_key: DOMAIN,
            origin_app: vec![0xAB; 20],
            manifest_hash: [0x11; 32],
        };
        execute_graft_tx(&mut state, &ctx(registrant), &register).unwrap();
        let fee = state.registry.params().graft_registration_fee;
        assert_eq!(state.get_balance(&registrant), 100 - fee);
        let id = graft_id(DOMAIN, &[0xAB; 20]);
        let app = state.settlement.graft.get(&id).unwrap();
        assert_eq!(
            app.owner,
            Address::zero(),
            "the registrant gains no ownership"
        );
        // The same registration again changes nothing and costs nothing.
        execute_graft_tx(&mut state, &ctx(registrant), &register).unwrap();
        assert_eq!(state.get_balance(&registrant), 100 - fee);
        // An unknown domain is refused.
        let unknown = GraftTx::Register {
            domain_key: DOMAIN + 1,
            origin_app: vec![0xAB; 20],
            manifest_hash: [0x11; 32],
        };
        assert!(execute_graft_tx(&mut state, &ctx(registrant), &unknown).is_err());
    }

    #[test]
    fn payments_accrue_in_the_mirror_until_a_claim_sweeps_them() {
        let operator = Address::from([0x01; 32]);
        let user = Address::from([0x03; 32]);
        let payout = Address::from([0x04; 32]);
        let origin = vec![0xCD; 20];
        let mut state = state_with_domain(operator);
        state.add_balance(&user, 1_000);
        execute_graft_tx(
            &mut state,
            &ctx(user),
            &GraftTx::Register {
                domain_key: DOMAIN,
                origin_app: origin.clone(),
                manifest_hash: [0x11; 32],
            },
        )
        .unwrap();
        let id = graft_id(DOMAIN, &origin);
        let pay = GraftTx::Pay {
            graft_id: id,
            amount: 300,
            memo_hash: [0u8; 32],
            origin_recipient: vec![0x01],
        };
        execute_graft_tx(&mut state, &ctx(user), &pay).unwrap();
        assert_eq!(state.get_balance(&mirror_account(id)), 300);
        let payment_id = state.settlement.graft.payments[0].payment_id;
        let (payment, proof) = state.settlement.graft.payment_proof(&payment_id).unwrap();
        assert_eq!(payment.amount, 300);
        assert!(proof.verify(state.settlement.graft.payments_root()));

        // A claim event from another emitter is refused.
        let forged = message(
            Address::from([0x99; 32]),
            payout,
            claim_payload_hash(id, payout),
            GRAFT_CLAIM_KIND,
            id,
        );
        let evidence = anchored(&mut state, forged);
        let claim = |evidence| GraftTx::Claim {
            graft_id: id,
            payout,
            evidence,
        };
        assert!(execute_graft_tx(&mut state, &ctx(user), &claim(evidence)).is_err());

        // The application's own event names the payout: it becomes the
        // owner and collects what accrued.
        let genuine = message(
            origin_emitter(&origin),
            payout,
            claim_payload_hash(id, payout),
            GRAFT_CLAIM_KIND,
            id,
        );
        let evidence = anchored(&mut state, genuine);
        execute_graft_tx(&mut state, &ctx(user), &claim(evidence.clone())).unwrap();
        assert_eq!(state.settlement.graft.get(&id).unwrap().owner, payout);
        assert_eq!(state.get_balance(&payout), 300);
        assert_eq!(state.get_balance(&mirror_account(id)), 0);
        // The same event works once.
        assert!(execute_graft_tx(&mut state, &ctx(user), &claim(evidence)).is_err());
        // Later payments go straight to the owner.
        execute_graft_tx(&mut state, &ctx(user), &pay).unwrap();
        assert_eq!(state.get_balance(&payout), 600);
    }

    #[test]
    fn an_intent_pays_the_solver_and_the_app_only_on_a_proven_call() {
        let operator = Address::from([0x01; 32]);
        let user = Address::from([0x03; 32]);
        let solver = Address::from([0x05; 32]);
        let origin = vec![0xEF; 20];
        let executor = vec![0x77; 20];
        let mut state = state_with_domain(operator);
        state.add_balance(&user, 10_000);
        let bond = state.registry.params().min_stake;
        let epoch = state.epoch_index;
        state
            .registry
            .register(solver, crate::registry::role::roles::RELAYER, bond, epoch)
            .unwrap();
        execute_graft_tx(
            &mut state,
            &ctx(user),
            &GraftTx::Register {
                domain_key: DOMAIN,
                origin_app: origin.clone(),
                manifest_hash: [0x11; 32],
            },
        )
        .unwrap();
        let id = graft_id(DOMAIN, &origin);
        let open = GraftTx::OpenIntent {
            graft_id: id,
            call_hash: [0x22; 32],
            value: 0,
            max_payment: 1_000,
            solver_fee_cap: 100,
            service_price: 200,
            origin_beneficiary: vec![0x33; 20],
            deadline_block: 0,
        };
        // No executor named for the domain yet: no intent can be served.
        assert!(execute_graft_tx(&mut state, &ctx(user), &open).is_err());
        execute_graft_tx(
            &mut state,
            &ctx(operator),
            &GraftTx::SetExecutor {
                domain_key: DOMAIN,
                executor: executor.clone(),
            },
        )
        .unwrap();
        let before = state.get_balance(&user);
        execute_graft_tx(&mut state, &ctx(user), &open).unwrap();
        assert_eq!(state.get_balance(&user), before - 1_000);
        let intent = state
            .settlement
            .graft
            .intents
            .values()
            .next()
            .unwrap()
            .clone();
        execute_graft_tx(
            &mut state,
            &ctx(solver),
            &GraftTx::Bid {
                intent_id: intent.intent_id,
                cost: 400,
                fee: 50,
            },
        )
        .unwrap();
        // An event from the right executor about another call pays nothing.
        let mut other = intent.clone();
        other.call_hash = [0x23; 32];
        let wrong = message(
            origin_emitter(&executor),
            Address::zero(),
            fulfilled_payload_hash(&other, &origin, solver),
            GRAFT_FULFILLED_KIND,
            intent.intent_id,
        );
        let evidence = anchored(&mut state, wrong);
        let fulfil = |evidence| GraftTx::Fulfill {
            intent_id: intent.intent_id,
            evidence,
        };
        assert!(execute_graft_tx(&mut state, &ctx(solver), &fulfil(evidence)).is_err());

        let right = message(
            origin_emitter(&executor),
            Address::zero(),
            fulfilled_payload_hash(&intent, &origin, solver),
            GRAFT_FULFILLED_KIND,
            intent.intent_id,
        );
        let evidence = anchored(&mut state, right);
        execute_graft_tx(&mut state, &ctx(solver), &fulfil(evidence)).unwrap();
        assert_eq!(state.get_balance(&solver), 450);
        assert_eq!(state.get_balance(&mirror_account(id)), 200);
        assert_eq!(state.get_balance(&user), before - 1_000 + 350);
        assert!(state.settlement.graft.intents.is_empty());
    }

    #[test]
    fn an_expired_intent_refunds_the_user_and_slashes_its_bidders() {
        let operator = Address::from([0x01; 32]);
        let user = Address::from([0x03; 32]);
        let solver = Address::from([0x05; 32]);
        let origin = vec![0xEF; 20];
        let mut state = state_with_domain(operator);
        state.add_balance(&user, 10_000);
        let bond = state.registry.params().min_stake;
        let epoch = state.epoch_index;
        state
            .registry
            .register(solver, crate::registry::role::roles::RELAYER, bond, epoch)
            .unwrap();
        state
            .settlement
            .graft
            .register(DOMAIN, origin.clone(), [0x11; 32], 0)
            .unwrap();
        state
            .settlement
            .graft
            .executors
            .insert(DOMAIN, vec![0x77; 20]);
        let id = graft_id(DOMAIN, &origin);
        execute_graft_tx(
            &mut state,
            &ctx(user),
            &GraftTx::OpenIntent {
                graft_id: id,
                call_hash: [0x22; 32],
                value: 0,
                max_payment: 1_000,
                solver_fee_cap: 100,
                service_price: 0,
                origin_beneficiary: vec![0x33; 20],
                deadline_block: 10,
            },
        )
        .unwrap();
        let intent_id = *state.settlement.graft.intents.keys().next().unwrap();
        execute_graft_tx(
            &mut state,
            &ctx(solver),
            &GraftTx::Bid {
                intent_id,
                cost: 100,
                fee: 10,
            },
        )
        .unwrap();
        let refund = GraftTx::Refund { intent_id };
        assert!(execute_graft_tx(&mut state, &ctx(user), &refund).is_err());
        state.current_block_height = 11;
        let before = state.get_balance(&user);
        execute_graft_tx(&mut state, &ctx(user), &refund).unwrap();
        assert_eq!(state.get_balance(&user), before + 1_000);
        let stake = state
            .registry
            .get(&solver, crate::registry::role::roles::RELAYER)
            .unwrap()
            .stake;
        assert!(stake < bond, "the undelivered bid costs bond");
    }

    #[test]
    fn a_fee_share_goes_to_the_application_never_back_to_its_sender() {
        let operator = Address::from([0x01; 32]);
        let user = Address::from([0x03; 32]);
        let mut state = state_with_domain(operator);
        state
            .settlement
            .graft
            .register(DOMAIN, vec![0xAA; 20], [0x11; 32], 0)
            .unwrap();
        let id = graft_id(DOMAIN, &[0xAA; 20]);
        let pay = |from: Address| {
            crate::core::transaction::Transaction::new_with_chain_id(
                from,
                Address::zero(),
                0,
                FEE,
                0,
                Vec::new(),
                crate::core::transaction::DEFAULT_CHAIN_ID,
                crate::core::transaction::TransactionType::Settlement(
                    crate::settlement::domains::SettlementTx::Graft(Box::new(GraftTx::Pay {
                        graft_id: id,
                        amount: 1,
                        memo_hash: [0u8; 32],
                        origin_recipient: vec![1],
                    })),
                ),
            )
        };
        assert_eq!(
            application_fee_recipient(&state, &pay(user)),
            Some(mirror_account(id))
        );
        assert_eq!(
            application_fee_recipient(&state, &pay(mirror_account(id))),
            None
        );
    }

    /// Cross-language known answers: contracts/test/Parity.t.sol pins the
    /// same values for `GraftExecutor` and `BudlumGraftClaim`.
    #[test]
    fn event_payload_hashes_match_the_solidity_known_answers() {
        let intent = GraftIntent {
            intent_id: [0x11; 32],
            graft_id: [0u8; 32],
            owner: Address::zero(),
            call_hash: [0x33; 32],
            value: 7,
            max_payment: 0,
            solver_fee_cap: 0,
            service_price: 0,
            origin_beneficiary: vec![0x44; 20],
            deadline_block: 0,
            bids: Vec::new(),
        };
        assert_eq!(
            hex::encode(fulfilled_payload_hash(
                &intent,
                &[0x22; 20],
                Address::from([0x55; 32])
            )),
            "f7d3f98632aa75076903668db4def05736bf895dafa1e6f23c94d87c9a0b3192"
        );
        assert_eq!(
            hex::encode(claim_payload_hash([0x66; 32], Address::from([0x77; 32]))),
            "331af272e430b9515307696fd158d2eef3760d1e18c6cb5cc5f85450302b1e05"
        );
    }

    /// An externally owned application claims with its own key. The
    /// signature was made with Foundry's `cast wallet sign` over
    /// `eoa_claim_hash(45262, graft_id, [0x33; 32], 100)` by the key of
    /// 0x2c75..5c23.
    #[test]
    fn an_eoa_application_claims_with_its_personal_sign_signature() {
        const SIGNATURE: &str = "27d1945959111fba17d9bdf6ee6bf64a0766ef032ed198ea2fa323cf3df1b95566b864c77745d1fdc451f6236d06f453059576bccf5e09bffb34957a4468f9691c";
        let operator = Address::from([0x01; 32]);
        let registrant = Address::from([0x02; 32]);
        let mut state = state_with_domain(operator);
        state.add_balance(&registrant, 1_000_000);
        let eoa = hex::decode("2c7536e3605d9c16a7a3d7b1898e529396a65c23").unwrap();
        execute_graft_tx(
            &mut state,
            &ctx(registrant),
            &GraftTx::Register {
                domain_key: DOMAIN,
                origin_app: eoa.clone(),
                manifest_hash: [0x11; 32],
            },
        )
        .unwrap();
        let id = graft_id(DOMAIN, &eoa);
        assert_eq!(
            hex::encode(eoa_claim_hash(
                crate::core::transaction::DEFAULT_CHAIN_ID,
                id,
                Address::from([0x33; 32]),
                100
            )),
            "ee19ec77caea74d6ac05b20ac83896d27b65099cd97eac6f19ab4ba9cfe61aa5"
        );
        let claim = GraftTx::ClaimBySignature {
            graft_id: id,
            payout: Address::from([0x33; 32]),
            valid_until_block: 100,
            signature: hex::decode(SIGNATURE).unwrap(),
        };
        execute_graft_tx(&mut state, &ctx(registrant), &claim).expect("the key claims");
        assert_eq!(
            state.settlement.graft.get(&id).unwrap().owner,
            Address::from([0x33; 32])
        );
        assert!(
            execute_graft_tx(&mut state, &ctx(registrant), &claim).is_err(),
            "each signature works once"
        );
        let other_payout = GraftTx::ClaimBySignature {
            graft_id: id,
            payout: Address::from([0x34; 32]),
            valid_until_block: 100,
            signature: hex::decode(SIGNATURE).unwrap(),
        };
        assert!(execute_graft_tx(&mut state, &ctx(registrant), &other_payout).is_err());
    }
}
