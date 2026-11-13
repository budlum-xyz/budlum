//! WIRING: unwired - verify_app_binding_payment has no in-tree caller by design: bud_getapp_bindingPayment returns the proof to the caller, who verifies it against their own trust anchor (documented in rpc/api.rs).
//! WIRING: wired - registration, ownership claims, payments, solver intents,
//! bids, fulfilment and refunds run in block through `SettlementTx::app_binding`;
//! the Ethereum-side `app_bindingExecutor` contract is ().
//!
//! `app_binding`: an application that lives on another network is used from
//! Budlum and paid for in BUD, without moving there.
//!
//! A `app_binding` row binds an application on an origin domain to one deterministic,
//! keyless Budlum mirror account. Nothing leaves the mirror except by a rule
//! of this module; there is no administrator key.
//!
//! - **Register** is permissionless and idempotent. It names no owner: the
//!   registrant gains nothing over the application.
//! - **Claim** proves, from the origin domain, that the application itself
//!   names a Budlum payout address: an anchored `budlum/app_binding/claim/v1`
//!   event emitted by the application. The payout becomes the owner and the
//!   mirror balance moves to it. A later claim event rotates the owner.
//! - **Pay** moves BUD from a user to the application: to its owner, or into
//!   the mirror while nobody has claimed it.
//! - **`OpenIntent` / Bid / Award / Fulfill / Refund** let a user ask a solver
//!   to make a call on the origin chain. The owner awards the cheapest bid
//!   before any solver acts; that choice is frozen in consensus state. An
//!   anchored executor event then pays only that solver. On expiry the owner
//!   is refunded and only the awarded solver may be slashed.
//!
//! External evidence uses the anchored-result model of the bridge and the
//! relayer intents ([`crate::relayer::policy::verify_anchored_result`]): a
//! cross-domain message whose result leaf reaches the root consensus has
//! anchored for that domain.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::chain_config::app_binding_enabled_for_chain_id;
use crate::core::hash::hash_fields_bytes;
use crate::core::transaction::RelayerExternalResult;
use crate::cross_domain::message::MessageKind;
use crate::settlement::domains::{SettlementTxContext, SettlementTxError};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Event kind an origin application emits to name its Budlum payout.
pub const APP_BINDING_CLAIM_KIND: &[u8] = b"budlum/app_binding/claim/v1";
/// Event kind a domain's `app_binding` executor emits after carrying out a call.
pub const APP_BINDING_FULFILLED_KIND: &[u8] = b"budlum/app_binding/fulfilled/v1";
/// Upper bound of an origin application, executor or recipient identifier.
pub const MAX_APP_BINDING_IDENTIFIER_BYTES: usize = 256;
/// Registered applications held in state.
pub const MAX_APP_BINDING_APPS: usize = 10_000;
/// Recent payments held in state for payment proofs; older rows leave the
/// window (an indexer keeps the history).
pub const APP_BINDING_PAYMENT_WINDOW: usize = 10_000;
/// Open intents held in state.
pub const MAX_APP_BINDING_OPEN_INTENTS: usize = 10_000;
/// Unrefunded intents one sender may hold at once.
pub const MAX_BINDING_INTENTS_PER_SENDER: usize = 16;
/// Bids one intent may hold.
pub const MAX_APP_BINDING_BIDS_PER_INTENT: usize = 16;
/// Claim messages remembered for replay protection.
pub const MAX_APP_BINDING_USED_MESSAGES: usize = 100_000;
/// The farthest deadline an intent may name, in blocks from now.
pub const MAX_APP_BINDING_INTENT_HORIZON_BLOCKS: u64 = 100_000;
/// The award must leave a bidder time to act, rather than imposing a
/// liveness obligation on a bid just as the intent expires.
pub const MIN_APP_BINDING_AWARD_WINDOW_BLOCKS: u64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AppBindingStatus {
    #[default]
    Active,
    Paused,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBindingApp {
    pub app_binding_id: [u8; 32],
    /// The claimed owner; zero until a claim proves one.
    pub owner: Address,
    pub domain_key: u32,
    pub origin_app: Vec<u8>,
    /// B.U.D. content id of the application's metadata.
    pub manifest_hash: [u8; 32],
    pub mirror_account: Address,
    pub status: AppBindingStatus,
    pub registered_at_block: u64,
}

impl AppBindingApp {
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
pub struct AppBindingPayment {
    pub payment_id: [u8; 32],
    pub app_binding_id: [u8; 32],
    pub payer: Address,
    pub recipient: Address,
    pub amount: u64,
    pub origin_recipient: Vec<u8>,
    pub memo_hash: [u8; 32],
    pub paid_at_block: u64,
    #[serde(default)]
    pub target_chain_id: u64,
    #[serde(default)]
    pub target_receiver: Vec<u8>,
}

impl AppBindingPayment {
    /// The leaf a payment proof opens.
    #[must_use]
    pub fn leaf_hash(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_APP_BINDING_PAYMENT_LEAF_V1",
            &self.payment_id,
            &self.app_binding_id,
            self.payer.as_bytes(),
            self.recipient.as_bytes(),
            &self.amount.to_le_bytes(),
            &u64::try_from(self.origin_recipient.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
            &self.origin_recipient,
            &self.memo_hash,
            &self.paid_at_block.to_le_bytes(),
            &self.target_chain_id.to_le_bytes(),
            &u64::try_from(self.target_receiver.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
            &self.target_receiver,
        ])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBindingBid {
    pub solver: Address,
    /// What the solver spends on the origin chain, in BUD.
    pub cost: u64,
    /// The solver's fee, at most the intent's cap.
    pub fee: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBindingIntent {
    pub intent_id: [u8; 32],
    pub app_binding_id: [u8; 32],
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
    pub bids: Vec<AppBindingBid>,
    /// Once awarded, late bids cannot change the solver who may be paid.
    #[serde(default)]
    pub awarded_solver: Option<Address>,
    /// The domain executor identifier in force when this intent opened.
    ///
    /// `Fulfill` authenticates the anchored origin event against
    /// `origin_emitter(executor)`, so an intent that read the live pointer at
    /// fulfilment time was stranded by any later rotation - which is why
    /// rotation used to be refused outright while a single intent existed. The
    /// snapshot removes the veto: the operator may replace a compromised
    /// executor at any time, and work already awarded still proves against the
    /// emitter it was awarded against. Empty on rows written before the field
    /// existed, which fall back to the live pointer.
    #[serde(default)]
    pub executor: Vec<u8>,
}

/// State-rooted `app_binding` writes. Every variant is carried by a signed settlement
/// transaction, so the sender is `ctx.sender`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppBindingTx {
    /// Register an origin application. Permissionless, idempotent.
    Register {
        domain_key: u32,
        origin_app: Vec<u8>,
        manifest_hash: [u8; 32],
    },
    /// Prove the application names `payout` as its Budlum owner.
    Claim {
        app_binding_id: [u8; 32],
        payout: Address,
        evidence: Box<RelayerExternalResult>,
    },
    /// Pay the application in BUD.
    Pay {
        app_binding_id: [u8; 32],
        amount: u64,
        memo_hash: [u8; 32],
        origin_recipient: Vec<u8>,
        #[serde(default)]
        target_chain_id: u64,
        #[serde(default)]
        target_receiver: Vec<u8>,
    },
    /// Pause, resume or retire the application (owner only; retiring is
    /// final).
    SetStatus {
        app_binding_id: [u8; 32],
        status: AppBindingStatus,
    },
    /// Name the `app_binding` executor contract of a domain (that domain's operator
    /// only). Fulfilment events count only from this emitter.
    SetExecutor { domain_key: u32, executor: Vec<u8> },
    /// Ask a solver to make a call on the origin chain; escrow the maximum.
    OpenIntent {
        app_binding_id: [u8; 32],
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
        app_binding_id: [u8; 32],
        payout: Address,
        valid_until_block: u64,
        signature: Vec<u8>,
    },
    /// Freeze a specific solver's existing bid (owner only). Appended to
    /// preserve earlier bincode enum discriminants.
    Award {
        intent_id: [u8; 32],
        solver: Address,
    },
}

/// The 32-byte message an externally owned application signs (EIP-191
/// personal sign) to name its Budlum payout.
#[must_use]
pub fn eoa_claim_hash(
    chain_id: u64,
    app_binding_id: [u8; 32],
    payout: Address,
    valid_until_block: u64,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_APP_BINDING_EOA_CLAIM_V1",
        &chain_id.to_le_bytes(),
        &app_binding_id,
        payout.as_bytes(),
        &valid_until_block.to_le_bytes(),
    ])
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AppBindingRegistry {
    #[serde(with = "crate::core::map_keys")]
    pub apps: BTreeMap<[u8; 32], AppBindingApp>,
    /// The most recent payments, oldest first.
    pub payments: Vec<AppBindingPayment>,
    pub payment_count: u64,
    #[serde(with = "crate::core::map_keys")]
    pub intents: BTreeMap<[u8; 32], AppBindingIntent>,
    pub intent_count: u64,
    /// The `app_binding` executor of each domain, set by the domain's operator.
    pub executors: BTreeMap<u32, Vec<u8>>,
    /// Claim message ids already used: an anchored claim works once.
    pub used_messages: BTreeSet<[u8; 32]>,
}

/// What a payment proof needs besides the payment's own Merkle path: the
/// other half of the registry root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBindingRootOpening {
    pub payments_root: [u8; 32],
    pub rest_hash: [u8; 32],
}

impl AppBindingRootOpening {
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        hash_fields_bytes(&[
            b"BDLM_APP_BINDING_REGISTRY_V2",
            &self.payments_root,
            &self.rest_hash,
        ])
    }
}

/// The Merkle root of a payment window.
#[must_use]
pub fn window_root(payments: &[AppBindingPayment]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = payments.iter().map(AppBindingPayment::leaf_hash).collect();
    crate::settlement::commitment_tree::merkle_root(&leaves)
}

/// A payment of `payments` with its Merkle path to [`window_root`].
#[must_use]
pub fn window_proof(
    payments: &[AppBindingPayment],
    payment_id: &[u8; 32],
) -> Option<(
    AppBindingPayment,
    crate::cross_domain::event_tree::MerkleProof,
)> {
    let index = payments
        .iter()
        .position(|payment| &payment.payment_id == payment_id)?;
    let leaves: Vec<[u8; 32]> = payments.iter().map(AppBindingPayment::leaf_hash).collect();
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

/// Everything an application needs to check a `app_binding` payment itself
/// the payment, its path to the payment window root, the
/// other half of the registry root, and the checkpoint header that commits
/// that root with the material that ties the header to a finalized block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppBindingPaymentProof {
    pub payment: AppBindingPayment,
    pub path: crate::cross_domain::event_tree::MerkleProof,
    pub opening: AppBindingRootOpening,
    pub header: crate::settlement::GlobalBlockHeader,
    pub block_height: u64,
    pub state_root: String,
    pub state_root_body: Option<[u8; 32]>,
}

/// Why a `app_binding` payment proof does not hold.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AppBindingProofError {
    #[error("the payment does not hash to the proven leaf")]
    Leaf,
    #[error("the payment path does not reach the window root")]
    Path,
    #[error("the registry opening does not reproduce the header's AppBinding root")]
    Opening,
    #[error("the proof carries no state root opening for its checkpoint")]
    NoStateRootBody,
    #[error("the checkpoint lies outside the active payment window")]
    Window,
    #[error("the payment was made to a different bound application")]
    Application,
    #[error("the payment names a different chain or receiver than this deployment")]
    Receiver,
    #[error("the header is not the one the finalized checkpoint commits: {0}")]
    Header(String),
}

/// Check an application-binding payment proof against a finalized checkpoint the caller
/// already trusts (a [`crate::light_client::VerifiedCheckpoint`] reached
/// from its trust anchor) for one specific deployment. The chain checked
/// is: the payment's application and chain/receiver binding -> finalized
/// checkpoint -> state root -> global header -> binding root -> payment
/// window -> payment.
///
/// `expected_app_id` is the verifying application's own binding id, and
/// `expected_target_chain_id` / `expected_target_receiver` are that
/// deployment's chain and receiver (zero and empty when the payment names
/// none). A payment made to another application, chain or receiver is
/// refused.
///
/// # Errors
///
/// The first link that does not hold.
pub fn verify_app_binding_payment(
    proof: &AppBindingPaymentProof,
    checkpoint: &crate::light_client::VerifiedCheckpoint,
    expected_app_id: [u8; 32],
    expected_target_chain_id: u64,
    expected_target_receiver: &[u8],
) -> Result<(), AppBindingProofError> {
    if proof.path.leaf != proof.payment.leaf_hash() {
        return Err(AppBindingProofError::Leaf);
    }
    if proof.payment.app_binding_id != expected_app_id {
        return Err(AppBindingProofError::Application);
    }
    if proof.payment.target_chain_id != expected_target_chain_id
        || proof.payment.target_receiver.as_slice() != expected_target_receiver
    {
        return Err(AppBindingProofError::Receiver);
    }
    if !proof.path.verify(proof.opening.payments_root) {
        return Err(AppBindingProofError::Path);
    }
    if proof.header.app_binding_root != Some(proof.opening.root()) {
        return Err(AppBindingProofError::Opening);
    }
    if proof.header.checkpoint_height < proof.payment.paid_at_block
        || proof.header.checkpoint_height - proof.payment.paid_at_block
            > APP_BINDING_PAYMENT_WINDOW as u64
    {
        return Err(AppBindingProofError::Window);
    }
    let body = proof
        .state_root_body
        .ok_or(AppBindingProofError::NoStateRootBody)?;
    crate::light_client::LightClient::verify_global_header(checkpoint, &body, &proof.header)
        .map_err(|e| AppBindingProofError::Header(e.to_string()))
}

/// `H("BDLM_APP_BINDING_APP_V1", domain_key, origin_app)`.
#[must_use]
pub fn app_binding_id(domain_key: u32, origin_app: &[u8]) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_APP_BINDING_APP_V1",
        &domain_key.to_le_bytes(),
        &u64::try_from(origin_app.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
        origin_app,
    ])
}

/// `H("BDLM_APP_BINDING_MIRROR_V1", app_binding_id)`: an address no key controls.
#[must_use]
pub fn mirror_account(app_binding_id: [u8; 32]) -> Address {
    Address::from(hash_fields_bytes(&[
        b"BDLM_APP_BINDING_MIRROR_V1",
        &app_binding_id,
    ]))
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
            b"BDLM_APP_BINDING_ORIGIN_EMITTER_V1",
            origin,
        ]))
    }
}

/// The payload hash of the claim event an application emits.
#[must_use]
pub fn claim_payload_hash(app_binding_id: [u8; 32], payout: Address) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_APP_BINDING_CLAIM_EVENT_V1",
        &app_binding_id,
        payout.as_bytes(),
    ])
}

/// The payload hash of the fulfilment event the executor emits: the intent,
/// the target, the call, the value, the beneficiary and the solver.
#[must_use]
pub fn fulfilled_payload_hash(
    intent: &AppBindingIntent,
    origin_app: &[u8],
    solver: Address,
) -> [u8; 32] {
    hash_fields_bytes(&[
        b"BDLM_APP_BINDING_FULFILLED_EVENT_V1",
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
    !bytes.is_empty() && bytes.len() <= MAX_APP_BINDING_IDENTIFIER_BYTES
}

fn ensure_serving_origin(state: &AccountState, domain_key: u32) -> Result<(), SettlementTxError> {
    let domain = state
        .settlement
        .domains
        .get(domain_key)
        .ok_or_else(|| refused("app-binding origin is not a registered domain"))?;
    if !domain.is_active() || !domain.bridge_enabled {
        return Err(refused(
            "app-binding origin domain is not active with finality anchoring",
        ));
    }
    Ok(())
}

fn encoded(value: &impl Serialize) -> Vec<u8> {
    bincode::serialize(value).unwrap_or_else(|_| b"BDLM_APP_BINDING_UNENCODABLE_V1".to_vec())
}

impl AppBindingRegistry {
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
    pub fn opening(&self) -> AppBindingRootOpening {
        let rest_hash = hash_fields_bytes(&[
            b"BDLM_APP_BINDING_REST_V1",
            &encoded(&self.apps),
            &self.payment_count.to_le_bytes(),
            &encoded(&self.intents),
            &self.intent_count.to_le_bytes(),
            &encoded(&self.executors),
            &encoded(&self.used_messages),
        ]);
        AppBindingRootOpening {
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
    pub fn get(&self, app_binding_id: &[u8; 32]) -> Option<&AppBindingApp> {
        self.apps.get(app_binding_id)
    }

    /// The application whose mirror account is `mirror`, if any.
    #[must_use]
    pub fn by_mirror(&self, mirror: &Address) -> Option<&AppBindingApp> {
        self.apps.values().find(|app| &app.mirror_account == mirror)
    }

    /// A payment still in the window, with its Merkle path to
    /// [`Self::payments_root`].
    #[must_use]
    /// WIRING: unwired - no caller in this tree yet; kept as a declared surface, and nothing depends on it until one arrives.
    pub fn payment_proof(
        &self,
        payment_id: &[u8; 32],
    ) -> Option<(
        AppBindingPayment,
        crate::cross_domain::event_tree::MerkleProof,
    )> {
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
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn register(
        &mut self,
        domain_key: u32,
        origin_app: Vec<u8>,
        manifest_hash: [u8; 32],
        block: u64,
    ) -> Result<bool, String> {
        if !identifier_ok(&origin_app) {
            return Err("AppBinding origin_app length is invalid".into());
        }
        if manifest_hash == [0u8; 32] {
            return Err("AppBinding manifest_hash cannot be zero".into());
        }
        let id = app_binding_id(domain_key, &origin_app);
        if let Some(existing) = self.apps.get(&id) {
            if existing.manifest_hash == manifest_hash {
                return Ok(false);
            }
            return Err(
                "AppBinding application is already registered with another manifest".into(),
            );
        }
        if self.apps.len() >= MAX_APP_BINDING_APPS {
            return Err("AppBinding application registry is full".into());
        }
        self.apps.insert(
            id,
            AppBindingApp {
                app_binding_id: id,
                owner: Address::zero(),
                domain_key,
                origin_app,
                manifest_hash,
                mirror_account: mirror_account(id),
                status: AppBindingStatus::Active,
                registered_at_block: block,
            },
        );
        Ok(true)
    }

    fn record_payment(&mut self, mut payment: AppBindingPayment) -> [u8; 32] {
        payment.payment_id = hash_fields_bytes(&[
            b"BDLM_APP_BINDING_PAYMENT_V1",
            &payment.app_binding_id,
            payment.payer.as_bytes(),
            &self.payment_count.to_le_bytes(),
        ]);
        self.payment_count = self.payment_count.saturating_add(1);
        let id = payment.payment_id;
        self.payments.push(payment);
        if self.payments.len() > APP_BINDING_PAYMENT_WINDOW {
            let excess = self.payments.len() - APP_BINDING_PAYMENT_WINDOW;
            self.payments.drain(..excess);
        }
        id
    }
}

/// The account that receives the application share of `tx`'s protocol fee.
///
/// Only a registered, active `app_binding` application earns a share, and the
/// application is identified from the transaction's own effect: the `app_binding` id
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
    if !app_binding_enabled_for_chain_id(tx.chain_id) {
        return None;
    }
    let registry = &state.settlement.app_binding;
    let app = match &tx.tx_type {
        TransactionType::ContractCall if tx.to != Address::zero() => registry.by_mirror(&tx.to),
        TransactionType::Settlement(SettlementTx::AppBinding(app_binding_tx)) => {
            match app_binding_tx.as_ref() {
                AppBindingTx::Pay { app_binding_id, .. }
                | AppBindingTx::OpenIntent { app_binding_id, .. } => registry.get(app_binding_id),
                _ => None,
            }
        }
        _ => None,
    }?;
    if app.status != AppBindingStatus::Active
        || ensure_serving_origin(state, app.domain_key).is_err()
    {
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
    app: &AppBindingApp,
    app_binding_id: &[u8; 32],
    payout: Address,
    proof_id: [u8; 32],
) -> Result<(), SettlementTxError> {
    // Preflight all fallible balance arithmetic before changing the owner or
    // consuming a one-use proof. Otherwise a payout overflow leaves the claim
    // recorded even though the transaction was refused (G-4).
    let swept = state.get_balance(&app.mirror_account);
    if swept > 0 && payout != app.mirror_account {
        state
            .get_balance(&payout)
            .checked_add(swept)
            .ok_or_else(|| refused("app-binding payout would overflow"))?;
    }
    let registry = &mut state.settlement.app_binding;
    if registry.used_messages.contains(&proof_id) {
        return Err(refused("AppBinding claim proof has already been used"));
    }
    if registry.used_messages.len() >= MAX_APP_BINDING_USED_MESSAGES {
        return Err(refused("AppBinding claim replay set is full"));
    }
    registry.used_messages.insert(proof_id);
    if let Some(row) = registry.apps.get_mut(app_binding_id) {
        row.owner = payout;
    }
    // Everything that accrued while nobody owned the application moves to
    // its owner now.
    if swept > 0 {
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
        .ok_or_else(|| refused("AppBinding amount overflows"))?;
    let balance = state.spendable_balance(&ctx.sender);
    if balance < needed {
        return Err(SettlementTxError::BondUnfunded { needed, balance });
    }
    let account = state.get_or_create(&ctx.sender);
    account.balance = account
        .balance
        .checked_sub(amount)
        .ok_or_else(|| refused("AppBinding debit underflow"))?;
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

/// Check all recipients together before consuming an intent or paying anyone.
/// One account may fill several roles (solver, owner, application), so each
/// individual credit fitting is not enough to prove the total fits.
fn preflight_credits(
    state: &AccountState,
    payments: &[(Address, u64)],
) -> Result<(), SettlementTxError> {
    let mut totals = BTreeMap::<Address, u64>::new();
    for (address, amount) in payments {
        let total = totals.entry(*address).or_default();
        *total = total
            .checked_add(*amount)
            .ok_or_else(|| refused("app-binding payout would overflow"))?;
    }
    for (address, total) in totals {
        state
            .get_balance(&address)
            .checked_add(total)
            .ok_or_else(|| refused("app-binding payout would overflow"))?;
    }
    Ok(())
}

/// Execute one `app_binding` transaction through the settlement door.
///
/// # Errors
///
/// Returns an error if the operation fails.
pub fn execute_app_binding_tx(
    state: &mut AccountState,
    ctx: &SettlementTxContext,
    tx: &AppBindingTx,
) -> Result<(), SettlementTxError> {
    // Remote application binding is open from genesis on testnet (45261) and
    // devnet (45262), and remains closed on mainnet (45260) unless explicitly
    // activated. Refuse before registry or balances move, including direct callers
    // that bypass the outer settlement door.
    if !app_binding_enabled_for_chain_id(ctx.chain_id) {
        return Err(refused("app_binding is not enabled on this chain"));
    }
    let block = state.current_block_height;
    match tx {
        AppBindingTx::Register {
            domain_key,
            origin_app,
            manifest_hash,
        } => {
            ensure_serving_origin(state, *domain_key)?;
            if let Some(executor) = state.settlement.app_binding.executors.get(domain_key) {
                if executor.len() != origin_app.len() {
                    return Err(refused(
                        "the AppBinding application's identifier width does not match its domain's executor",
                    ));
                }
            }
            let registration_fee = state.registry.params().app_binding_registration_fee;
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
            // Burn accounting must not saturate or fail after registration has
            // already changed the registry. Preflight the next value first.
            let next_burned = state
                .burned_total
                .checked_add(registration_fee)
                .ok_or_else(|| refused("app-binding registration burn accounting overflows"))?;
            let written = state
                .settlement
                .app_binding
                .register(*domain_key, origin_app.clone(), *manifest_hash, block)
                .map_err(SettlementTxError::Refused)?;
            if written {
                // The registration fee is destroyed, and recorded as such
                // so it does not reopen mint headroom under the cap.
                debit(state, ctx, registration_fee)?;
                state.burned_total = next_burned;
            }
            Ok(())
        }
        AppBindingTx::Claim {
            app_binding_id,
            payout,
            evidence,
        } => {
            if *payout == Address::zero() {
                return Err(refused("AppBinding payout cannot be zero"));
            }
            let app = state
                .settlement
                .app_binding
                .get(app_binding_id)
                .cloned()
                .ok_or_else(|| refused("AppBinding application not found"))?;
            if app.status == AppBindingStatus::Retired {
                return Err(refused(
                    "a retired AppBinding application cannot be claimed",
                ));
            }
            if !state
                .settlement
                .domains
                .get(app.domain_key)
                .is_some_and(crate::domain::types::ConsensusDomain::is_active)
            {
                return Err(refused("the remote app binding's domain is not Active"));
            }
            if evidence.chain.domain_id() != app.domain_key {
                return Err(refused(
                    "AppBinding claim evidence comes from another domain",
                ));
            }
            let message =
                crate::relayer::policy::verify_anchored_result(&state.external_roots, evidence)
                    .map_err(SettlementTxError::Refused)?;
            if message.kind != MessageKind::Custom(APP_BINDING_CLAIM_KIND.to_vec())
                || message.correlation_id != Some(*app_binding_id)
                || message.sender != origin_emitter(&app.origin_app)
                || message.recipient != *payout
                || message.payload_hash != claim_payload_hash(*app_binding_id, *payout)
            {
                return Err(refused(
                    "AppBinding claim event does not bind the application and the payout",
                ));
            }
            let message_id = message.message_id;
            apply_claim(state, &app, app_binding_id, *payout, message_id)
        }
        AppBindingTx::ClaimBySignature {
            app_binding_id,
            payout,
            valid_until_block,
            signature,
        } => {
            if *payout == Address::zero() {
                return Err(refused("AppBinding payout cannot be zero"));
            }
            if block > *valid_until_block {
                return Err(refused("the AppBinding claim signature has expired"));
            }
            if *valid_until_block > block.saturating_add(MAX_APP_BINDING_INTENT_HORIZON_BLOCKS) {
                return Err(refused(
                    "the AppBinding claim signature is valid too far ahead",
                ));
            }
            let app = state
                .settlement
                .app_binding
                .get(app_binding_id)
                .cloned()
                .ok_or_else(|| refused("AppBinding application not found"))?;
            if app.status == AppBindingStatus::Retired {
                return Err(refused(
                    "a retired AppBinding application cannot be claimed",
                ));
            }
            if !state
                .settlement
                .domains
                .get(app.domain_key)
                .is_some_and(crate::domain::types::ConsensusDomain::is_active)
            {
                return Err(refused("the remote app binding's domain is not Active"));
            }
            let eoa: [u8; 20] = app
                .origin_app
                .as_slice()
                .try_into()
                .map_err(|_| refused("only a 20-byte account can claim by signature"))?;
            let digest = crate::crypto::secp256k1_recover::eip191_digest(&eoa_claim_hash(
                ctx.chain_id,
                *app_binding_id,
                *payout,
                *valid_until_block,
            ));
            let signer = crate::crypto::secp256k1_recover::recover_address(&digest, signature)
                .map_err(|e| refused(e.to_string()))?;
            if signer != eoa {
                return Err(refused(
                    "the AppBinding claim signature is not the application's key",
                ));
            }
            apply_claim(state, &app, app_binding_id, *payout, digest)
        }
        AppBindingTx::Pay {
            app_binding_id,
            amount,
            memo_hash,
            origin_recipient,
            target_chain_id,
            target_receiver,
        } => {
            if *amount == 0 {
                return Err(refused("AppBinding payment amount must be non-zero"));
            }
            if !identifier_ok(origin_recipient) {
                return Err(refused("AppBinding origin_recipient length is invalid"));
            }
            if target_receiver.len() > MAX_APP_BINDING_IDENTIFIER_BYTES
                || (*target_chain_id != 0) != (!target_receiver.is_empty())
            {
                return Err(refused(
                    "app-binding target_chain_id and target_receiver must be set together",
                ));
            }
            let app = state
                .settlement
                .app_binding
                .get(app_binding_id)
                .cloned()
                .ok_or_else(|| refused("AppBinding application not found"))?;
            if app.status != AppBindingStatus::Active {
                return Err(refused("AppBinding application is not active"));
            }
            ensure_serving_origin(state, app.domain_key)?;
            let recipient = app.fee_recipient();
            if state.get_balance(&recipient).checked_add(*amount).is_none() {
                return Err(refused("AppBinding payment would overflow the recipient"));
            }
            if state.settlement.app_binding.payment_count == u64::MAX {
                return Err(refused("app-binding payment identifier space is exhausted"));
            }
            debit(state, ctx, *amount)?;
            credit(state, &recipient, *amount)?;
            state
                .settlement
                .app_binding
                .record_payment(AppBindingPayment {
                    payment_id: [0u8; 32],
                    app_binding_id: *app_binding_id,
                    payer: ctx.sender,
                    recipient,
                    amount: *amount,
                    origin_recipient: origin_recipient.clone(),
                    memo_hash: *memo_hash,
                    paid_at_block: block,
                    target_chain_id: *target_chain_id,
                    target_receiver: target_receiver.clone(),
                });
            Ok(())
        }
        AppBindingTx::SetStatus {
            app_binding_id,
            status,
        } => {
            let app = state
                .settlement
                .app_binding
                .apps
                .get_mut(app_binding_id)
                .ok_or_else(|| refused("AppBinding application not found"))?;
            if app.owner == Address::zero() || app.owner != ctx.sender {
                return Err(refused(
                    "only the claimed AppBinding owner may change its status",
                ));
            }
            if app.status == AppBindingStatus::Retired {
                return Err(refused("a retired AppBinding application stays retired"));
            }
            app.status = *status;
            Ok(())
        }
        AppBindingTx::SetExecutor {
            domain_key,
            executor,
        } => {
            let operator = state
                .settlement
                .domains
                .get(*domain_key)
                .ok_or_else(|| refused("AppBinding executor names an unregistered domain"))?
                .operator;
            if operator != Some(ctx.sender) {
                return Err(refused(
                    "only the domain operator may name its AppBinding executor",
                ));
            }
            if !identifier_ok(executor) {
                return Err(refused("AppBinding executor length is invalid"));
            }
            // Rotation is never refused for open intents. Each intent carries
            // the executor snapshot it was opened against, so replacing this
            // pointer cannot strand an awarded solver or turn one into a
            // liveness fault - and the veto it replaces was reachable by any
            // account holding the permissionless RELAYER bond: open one intent
            // against the domain, get it awarded, and the operator could not
            // rotate (not even away from a compromised executor) for the whole
            // 100_000-block horizon, renewable indefinitely.
            state
                .settlement
                .app_binding
                .executors
                .insert(*domain_key, executor.clone());
            Ok(())
        }
        AppBindingTx::OpenIntent {
            app_binding_id,
            call_hash,
            value,
            max_payment,
            solver_fee_cap,
            service_price,
            origin_beneficiary,
            deadline_block,
        } => {
            // Retire what is already past its deadline before measuring the
            // caps: an expired row is not work in progress, and counting it let
            // any funded account fill the registry with rows nobody will ever
            // fulfil (the escrow is refundable, so the only cost was the fee).
            sweep_expired_intents(state, block)?;
            let app = state
                .settlement
                .app_binding
                .get(app_binding_id)
                .cloned()
                .ok_or_else(|| refused("AppBinding application not found"))?;
            if app.status != AppBindingStatus::Active {
                return Err(refused("AppBinding application is not active"));
            }
            ensure_serving_origin(state, app.domain_key)?;
            let executor = state
                .settlement
                .app_binding
                .executors
                .get(&app.domain_key)
                .cloned()
                .ok_or_else(|| refused("the AppBinding application's domain has no executor"))?;
            // The executor emits the application's identifier in the
            // fulfilment preimage, so an application whose identifier is a
            // different width than the executor's own can never be fulfilled.
            if executor.len() != app.origin_app.len() {
                return Err(refused(
                    "the AppBinding application's identifier width does not match its domain's executor",
                ));
            }
            if *call_hash == [0u8; 32] {
                return Err(refused("AppBinding call_hash cannot be zero"));
            }
            if !identifier_ok(origin_beneficiary) {
                return Err(refused("AppBinding origin_beneficiary length is invalid"));
            }
            let reserved = solver_fee_cap
                .checked_add(*service_price)
                .ok_or_else(|| refused("AppBinding intent prices overflow"))?;
            if *max_payment == 0 || reserved > *max_payment {
                return Err(refused(
                    "AppBinding max_payment must cover the solver fee cap and the service price",
                ));
            }
            let deadline = if *deadline_block == 0 {
                block.saturating_add(
                    state
                        .registry
                        .params()
                        .app_binding_default_intent_deadline_blocks,
                )
            } else {
                *deadline_block
            };
            if deadline <= block
                || deadline > block.saturating_add(MAX_APP_BINDING_INTENT_HORIZON_BLOCKS)
            {
                return Err(refused("AppBinding intent deadline is out of range"));
            }
            let registry = &state.settlement.app_binding;
            let sender_rows = registry
                .intents
                .values()
                .filter(|intent| intent.owner == ctx.sender)
                .count();
            if sender_rows >= MAX_BINDING_INTENTS_PER_SENDER {
                return Err(refused("too many open intents for this account"));
            }
            // Every surviving row is live: the sweep above retired the expired
            // ones, so the registry cap and the per-account cap count the same
            // population and neither can be filled with rows that will never be
            // fulfilled.
            if registry.intents.len() >= MAX_APP_BINDING_OPEN_INTENTS {
                return Err(refused("AppBinding intent registry is full"));
            }
            let next_count = registry
                .intent_count
                .checked_add(1)
                .ok_or_else(|| refused("app-binding intent identifier space is exhausted"))?;
            let intent_id = hash_fields_bytes(&[
                b"BDLM_APP_BINDING_INTENT_V1",
                app_binding_id,
                ctx.sender.as_bytes(),
                call_hash,
                &registry.intent_count.to_le_bytes(),
            ]);
            if registry.intents.contains_key(&intent_id) {
                return Err(refused("app-binding intent identifier is already in use"));
            }
            debit(state, ctx, *max_payment)?;
            let registry = &mut state.settlement.app_binding;
            registry.intent_count = next_count;
            registry.intents.insert(
                intent_id,
                AppBindingIntent {
                    intent_id,
                    app_binding_id: *app_binding_id,
                    owner: ctx.sender,
                    call_hash: *call_hash,
                    value: *value,
                    max_payment: *max_payment,
                    solver_fee_cap: *solver_fee_cap,
                    service_price: *service_price,
                    origin_beneficiary: origin_beneficiary.clone(),
                    deadline_block: deadline,
                    bids: Vec::new(),
                    awarded_solver: None,
                    executor,
                },
            );
            Ok(())
        }
        AppBindingTx::Bid {
            intent_id,
            cost,
            fee,
        } => {
            if !state
                .registry
                .is_active(&ctx.sender, crate::registry::role::roles::RELAYER)
            {
                return Err(refused("an AppBinding bid requires an active RELAYER bond"));
            }
            let intent = state
                .settlement
                .app_binding
                .intents
                .get_mut(intent_id)
                .ok_or_else(|| refused("AppBinding intent not found"))?;
            if block > intent.deadline_block {
                return Err(refused("AppBinding intent has expired"));
            }
            if intent.awarded_solver.is_some() {
                return Err(refused("AppBinding auction is already awarded"));
            }
            let total = cost
                .checked_add(*fee)
                .and_then(|sum| sum.checked_add(intent.service_price))
                .ok_or_else(|| refused("AppBinding bid overflows"))?;
            if *fee > intent.solver_fee_cap || total > intent.max_payment {
                return Err(refused(
                    "AppBinding bid exceeds the intent's fee cap or payment",
                ));
            }
            if intent.bids.iter().any(|bid| bid.solver == ctx.sender) {
                return Err(refused("this solver has already bid on the intent"));
            }
            if intent.bids.len() >= MAX_APP_BINDING_BIDS_PER_INTENT {
                return Err(refused("AppBinding intent bid limit reached"));
            }
            intent.bids.push(AppBindingBid {
                solver: ctx.sender,
                cost: *cost,
                fee: *fee,
            });
            Ok(())
        }
        AppBindingTx::Award { intent_id, solver } => {
            let intent = state
                .settlement
                .app_binding
                .intents
                .get_mut(intent_id)
                .ok_or_else(|| refused("AppBinding intent not found"))?;
            if intent.owner != ctx.sender {
                return Err(refused("only the intent owner may award an AppBinding bid"));
            }
            if intent.awarded_solver.is_some() {
                return Err(refused("AppBinding auction is already awarded"));
            }
            if intent.deadline_block.saturating_sub(block) < MIN_APP_BINDING_AWARD_WINDOW_BLOCKS {
                return Err(refused("AppBinding award leaves too little time to fulfil"));
            }
            let winner = intent
                .bids
                .iter()
                .find(|bid| bid.solver == *solver)
                .ok_or_else(|| refused("selected solver has not bid on the AppBinding intent"))?
                .solver;
            intent.awarded_solver = Some(winner);
            Ok(())
        }
        AppBindingTx::Fulfill {
            intent_id,
            evidence,
        } => {
            let intent = state
                .settlement
                .app_binding
                .intents
                .get(intent_id)
                .cloned()
                .ok_or_else(|| refused("AppBinding intent not found"))?;
            if block > intent.deadline_block {
                return Err(refused("AppBinding intent has expired"));
            }
            if intent.awarded_solver != Some(ctx.sender) {
                return Err(refused("the sender is not the awarded AppBinding solver"));
            }
            let bid = intent
                .bids
                .iter()
                .find(|bid| bid.solver == ctx.sender)
                .cloned()
                .ok_or_else(|| refused("the awarded AppBinding bid is missing"))?;
            let app = state
                .settlement
                .app_binding
                .get(&intent.app_binding_id)
                .cloned()
                .ok_or_else(|| refused("AppBinding application not found"))?;
            if !state
                .settlement
                .domains
                .get(app.domain_key)
                .is_some_and(crate::domain::types::ConsensusDomain::is_active)
            {
                return Err(refused("the remote app binding's domain is not Active"));
            }
            // The intent's own snapshot decides which emitter may prove this
            // call, so a rotation after the award cannot invalidate work the
            // solver was awarded and already performed. Rows written before the
            // field existed carry no snapshot and read the live pointer.
            let executor = if intent.executor.is_empty() {
                state
                    .settlement
                    .app_binding
                    .executors
                    .get(&app.domain_key)
                    .cloned()
                    .ok_or_else(|| refused("the AppBinding application's domain has no executor"))?
            } else {
                intent.executor.clone()
            };
            if evidence.chain.domain_id() != app.domain_key {
                return Err(refused(
                    "AppBinding fulfilment evidence comes from another domain",
                ));
            }
            let message =
                crate::relayer::policy::verify_anchored_result(&state.external_roots, evidence)
                    .map_err(SettlementTxError::Refused)?;
            if message.kind != MessageKind::Custom(APP_BINDING_FULFILLED_KIND.to_vec())
                || message.correlation_id != Some(*intent_id)
                || message.sender != origin_emitter(&executor)
                || message.payload_hash
                    != fulfilled_payload_hash(&intent, &app.origin_app, ctx.sender)
            {
                return Err(refused(
                    "AppBinding fulfilment event does not prove this call for this intent",
                ));
            }
            let solver_paid = bid
                .cost
                .checked_add(bid.fee)
                .ok_or_else(|| refused("AppBinding bid overflows"))?;
            let refund = intent
                .max_payment
                .checked_sub(solver_paid)
                .and_then(|left| left.checked_sub(intent.service_price))
                .ok_or_else(|| refused("AppBinding escrow does not cover the bid"))?;
            let recipient = app.fee_recipient();
            preflight_credits(
                state,
                &[
                    (ctx.sender, solver_paid),
                    (recipient, intent.service_price),
                    (intent.owner, refund),
                ],
            )?;
            state.settlement.app_binding.intents.remove(intent_id);
            credit(state, &ctx.sender, solver_paid)?;
            credit(state, &recipient, intent.service_price)?;
            credit(state, &intent.owner, refund)?;
            Ok(())
        }
        AppBindingTx::Refund { intent_id } => {
            let intent = state
                .settlement
                .app_binding
                .intents
                .get(intent_id)
                .cloned()
                .ok_or_else(|| refused("AppBinding intent not found"))?;
            if block <= intent.deadline_block {
                return Err(refused("AppBinding intent has not expired"));
            }
            preflight_credits(state, &[(intent.owner, intent.max_payment)])?;
            settle_expired_intent(state, &intent)
        }
    }
}

/// Retire one intent that is past its deadline: drop the row, settle the
/// awarded solver's liveness fault if it could still have delivered, and return
/// the owner's escrow.
///
/// Shared by the `Refund` transaction and the block-end sweep so the two cannot
/// diverge: whichever runs first settles the intent, and the second finds no row
/// and does nothing (so a refund after the sweep is not a double payment).
fn settle_expired_intent(
    state: &mut AccountState,
    intent: &AppBindingIntent,
) -> Result<(), SettlementTxError> {
    if state
        .settlement
        .app_binding
        .intents
        .remove(&intent.intent_id)
        .is_none()
    {
        return Ok(());
    }
    // Bidding alone is not a promise to execute: only the solver actually
    // awarded the work held it open.
    if let Some(solver) = intent.awarded_solver {
        // `Fulfill` refuses an application whose domain is not Active, so a
        // solver awarded that work could not deliver it. A liveness fault
        // belongs to the solver only while the domain still lets it act; the
        // refund must not burn the bond of a solver that was never able to
        // fulfil. An intent with its own executor snapshot can be fulfilled
        // whatever the live pointer now says.
        let domain_deliverable = state
            .settlement
            .app_binding
            .get(&intent.app_binding_id)
            .is_some_and(|app| {
                state
                    .settlement
                    .domains
                    .get(app.domain_key)
                    .is_some_and(crate::domain::types::ConsensusDomain::is_active)
                    && (!intent.executor.is_empty()
                        || state
                            .settlement
                            .app_binding
                            .executors
                            .contains_key(&app.domain_key))
            });
        // `slash_role_only` refuses a registration that is already `Slashed`
        // or `SlashedUnbonding`, so gating on `is_slashable()` (which accepts
        // `SlashedUnbonding`) made the block-end sweep abort the whole block
        // transition for that solver: the intent row was removed, the slash
        // error propagated, the transition was discarded, and every later
        // block retried the same sweep and failed the same way. Only the
        // statuses the slash itself accepts count here, and an
        // `AlreadySlashed` refusal is a no-op: the solver was already
        // punished, and the owner's refund must not depend on a second
        // penalty succeeding.
        let slashable = state
            .registry
            .get(&solver, crate::registry::role::roles::RELAYER)
            .is_some_and(|registration| {
                registration.stake > 0
                    && matches!(
                        registration.status,
                        crate::registry::permissionless::MemberStatus::Active
                            | crate::registry::permissionless::MemberStatus::Unbonding { .. }
                    )
            });
        if domain_deliverable && slashable {
            let ratio = state.registry.params().liveness_slash_ratio_fixed;
            // Same rule as `RelayerIntentTx::Expire`: the escrow refund is not
            // welded to the penalty. `is_slashable()` accepts
            // `SlashedUnbonding`, `slash_role_only` refuses it with
            // `AlreadySlashed`, and propagating that here aborted the block-end
            // sweep, so every following expired intent stayed in the map and
            // the owner's escrow stayed locked. An already-punished solver has
            // nothing left to take; that is not a reason to keep the owner's
            // money.
            match state.slash_role_destroying(
                solver,
                crate::registry::role::roles::RELAYER,
                crate::registry::permissionless::SlashingCondition::LivenessFault,
                ratio,
            ) {
                Ok(_) => {}
                Err(crate::registry::RegistryError::AlreadySlashed { .. })
                | Err(crate::registry::RegistryError::NotRegistered { .. }) => {}
                Err(e) => return Err(refused(e.to_string())),
            }
        }
    }
    credit(state, &intent.owner, intent.max_payment)
}

/// Retire every AppBinding intent past its deadline, deterministically, at the block
/// height the transition is applying.
///
/// Only `Fulfill` and `Refund` removed a row before this, and both need a
/// transaction: an intent whose owner never came back stayed in `intents` for
/// the life of the chain, in the registry root, in `total_escrowed_supply` and
/// in every per-block scan of the map - and since the registry cap stopped
/// counting expired rows, nothing bounded how many a funded account could
/// accumulate. Runs inside the `(state, block) -> state` transition, so live
/// application, replay and reorg all retire the same rows at the same height.
pub(crate) fn sweep_expired_intents(
    state: &mut AccountState,
    block: u64,
) -> Result<(), SettlementTxError> {
    let expired: Vec<AppBindingIntent> = state
        .settlement
        .app_binding
        .intents
        .values()
        .filter(|intent| block > intent.deadline_block)
        .cloned()
        .collect();
    for intent in &expired {
        settle_expired_intent(state, intent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::app_binding_id as calc_binding_id;
    use super::execute_app_binding_tx as run_binding_tx;
    use super::AppBindingTx as BindingTx;
    use super::APP_BINDING_CLAIM_KIND as CLAIM_KIND;
    use super::APP_BINDING_FULFILLED_KIND as FULFILLED_KIND;
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
        let id = calc_binding_id(7, b"app");
        assert_eq!(id, calc_binding_id(7, b"app"));
        assert_ne!(id, calc_binding_id(8, b"app"));
        assert_ne!(mirror_account(id), Address::zero());
        assert_eq!(origin_emitter(&[0xAB; 20]).as_bytes()[12..], [0xAB; 20]);
        assert_eq!(origin_emitter(&[0xAB; 20]).as_bytes()[..12], [0u8; 12]);
    }

    #[test]
    fn binding_registration_refuses_burn_overflow_before_registry_write() {
        let operator = Address::from([0x01; 32]);
        let registrant = Address::from([0x02; 32]);
        let mut state = state_with_domain(operator);
        state.add_balance(&registrant, 100);
        state.burned_total = u64::MAX;
        let before = state.settlement.app_binding.root();
        let result = execute_app_binding_tx(
            &mut state,
            &ctx(registrant),
            &BindingTx::Register {
                domain_key: DOMAIN,
                origin_app: vec![0xAB; 20],
                manifest_hash: [0x11; 32],
            },
        );
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("burn accounting overflows"));
        assert_eq!(state.settlement.app_binding.root(), before);
        assert_eq!(state.get_balance(&registrant), 100);
        assert!(state.settlement.app_binding.apps.is_empty());
    }

    #[test]
    fn registration_is_permissionless_idempotent_and_ownerless() {
        let operator = Address::from([0x01; 32]);
        let registrant = Address::from([0x02; 32]);
        let mut state = state_with_domain(operator);
        state.add_balance(&registrant, 100);
        let register = BindingTx::Register {
            domain_key: DOMAIN,
            origin_app: vec![0xAB; 20],
            manifest_hash: [0x11; 32],
        };
        execute_app_binding_tx(&mut state, &ctx(registrant), &register).unwrap();
        let fee = state.registry.params().app_binding_registration_fee;
        assert_eq!(state.get_balance(&registrant), 100 - fee);
        let id = calc_binding_id(DOMAIN, &[0xAB; 20]);
        let app = state.settlement.app_binding.get(&id).unwrap();
        assert_eq!(
            app.owner,
            Address::zero(),
            "the registrant gains no ownership"
        );
        // The same registration again changes nothing and costs nothing.
        execute_app_binding_tx(&mut state, &ctx(registrant), &register).unwrap();
        assert_eq!(state.get_balance(&registrant), 100 - fee);
        // An unknown domain is refused.
        let unknown = BindingTx::Register {
            domain_key: DOMAIN + 1,
            origin_app: vec![0xAB; 20],
            manifest_hash: [0x11; 32],
        };
        assert!(execute_app_binding_tx(&mut state, &ctx(registrant), &unknown).is_err());
    }

    #[test]
    fn binding_id_counter_exhaustion_refuses_before_funds_move() {
        let operator = Address::from([0x01; 32]);
        let payer = Address::from([0x02; 32]);
        let mut state = state_with_domain(operator);
        state.add_balance(&payer, 2_000);
        let origin = vec![0xAB; 20];
        let id = calc_binding_id(DOMAIN, &origin);
        state
            .settlement
            .app_binding
            .register(DOMAIN, origin, [0x11; 32], 0)
            .unwrap();
        state
            .settlement
            .app_binding
            .executors
            .insert(DOMAIN, vec![0x77; 20]);
        state.settlement.app_binding.payment_count = u64::MAX;
        let before = state.settlement.app_binding.root();
        let pay = BindingTx::Pay {
            app_binding_id: id,
            amount: 1,
            memo_hash: [0; 32],
            origin_recipient: vec![0x33; 20],
            target_chain_id: 0,
            target_receiver: Vec::new(),
        };
        assert!(execute_app_binding_tx(&mut state, &ctx(payer), &pay).is_err());
        assert_eq!(state.settlement.app_binding.root(), before);
        assert_eq!(state.get_balance(&payer), 2_000);

        state.settlement.app_binding.intent_count = u64::MAX;
        let before = state.settlement.app_binding.root();
        let intent = BindingTx::OpenIntent {
            app_binding_id: id,
            call_hash: [0x22; 32],
            value: 0,
            max_payment: 100,
            solver_fee_cap: 10,
            service_price: 0,
            origin_beneficiary: vec![0x44; 20],
            deadline_block: 0,
        };
        assert!(execute_app_binding_tx(&mut state, &ctx(payer), &intent).is_err());
        assert_eq!(state.settlement.app_binding.root(), before);
        assert_eq!(state.get_balance(&payer), 2_000);
        assert!(state.settlement.app_binding.intents.is_empty());
    }

    #[test]
    fn binding_payout_preflight_aggregates_overlapping_recipient_roles() {
        let mut state = AccountState::new();
        let same_account = Address::from([0x79; 32]);
        state.add_balance(&same_account, u64::MAX - 4);
        assert!(preflight_credits(&state, &[(same_account, 3), (same_account, 3)]).is_err());
        assert_eq!(state.get_balance(&same_account), u64::MAX - 4);
    }

    #[test]
    fn rejected_binding_claim_does_not_consume_proof_or_change_owner() {
        let mut state = state_with_domain(Address::from([0x01; 32]));
        let origin = vec![0xAB; 20];
        let id = calc_binding_id(DOMAIN, &origin);
        state
            .settlement
            .app_binding
            .register(DOMAIN, origin, [0x11; 32], 0)
            .unwrap();
        let app = state.settlement.app_binding.get(&id).unwrap().clone();
        let payout = Address::from([0x77; 32]);
        let proof_id = [0x92; 32];
        state.add_balance(&app.mirror_account, 1);
        state.add_balance(&payout, u64::MAX);
        let before = state.settlement.app_binding.root();

        assert!(apply_claim(&mut state, &app, &id, payout, proof_id).is_err());
        assert_eq!(state.settlement.app_binding.root(), before);
        assert!(!state
            .settlement
            .app_binding
            .used_messages
            .contains(&proof_id));
        assert_eq!(
            state.settlement.app_binding.get(&id).unwrap().owner,
            Address::zero()
        );
        assert_eq!(state.get_balance(&app.mirror_account), 1);
        assert_eq!(state.get_balance(&payout), u64::MAX);
    }

    #[test]
    fn payments_accrue_in_the_mirror_until_a_claim_sweeps_them() {
        let operator = Address::from([0x01; 32]);
        let user = Address::from([0x03; 32]);
        let payout = Address::from([0x04; 32]);
        let origin = vec![0xCD; 20];
        let mut state = state_with_domain(operator);
        state.add_balance(&user, 1_000);
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &BindingTx::Register {
                domain_key: DOMAIN,
                origin_app: origin.clone(),
                manifest_hash: [0x11; 32],
            },
        )
        .unwrap();
        let id = calc_binding_id(DOMAIN, &origin);
        let pay = BindingTx::Pay {
            app_binding_id: id,
            amount: 300,
            memo_hash: [0u8; 32],
            origin_recipient: vec![0x01],
            target_chain_id: 1,
            target_receiver: vec![0x22; 20],
        };
        execute_app_binding_tx(&mut state, &ctx(user), &pay).unwrap();
        assert_eq!(state.get_balance(&mirror_account(id)), 300);
        let payment_id = state.settlement.app_binding.payments[0].payment_id;
        let (payment, proof) = state
            .settlement
            .app_binding
            .payment_proof(&payment_id)
            .unwrap();
        assert_eq!(payment.amount, 300);
        assert!(proof.verify(state.settlement.app_binding.payments_root()));

        // A claim event from another emitter is refused.
        let forged = message(
            Address::from([0x99; 32]),
            payout,
            claim_payload_hash(id, payout),
            APP_BINDING_CLAIM_KIND,
            id,
        );
        let evidence = anchored(&mut state, forged);
        let claim = |evidence| BindingTx::Claim {
            app_binding_id: id,
            payout,
            evidence,
        };
        assert!(execute_app_binding_tx(&mut state, &ctx(user), &claim(evidence)).is_err());

        // The application's own event names the payout: it becomes the
        // owner and collects what accrued.
        let genuine = message(
            origin_emitter(&origin),
            payout,
            claim_payload_hash(id, payout),
            APP_BINDING_CLAIM_KIND,
            id,
        );
        let evidence = anchored(&mut state, genuine);
        execute_app_binding_tx(&mut state, &ctx(user), &claim(evidence.clone())).unwrap();
        assert_eq!(state.settlement.app_binding.get(&id).unwrap().owner, payout);
        assert_eq!(state.get_balance(&payout), 300);
        assert_eq!(state.get_balance(&mirror_account(id)), 0);
        // The same event works once.
        assert!(execute_app_binding_tx(&mut state, &ctx(user), &claim(evidence)).is_err());
        // Later payments go straight to the owner.
        execute_app_binding_tx(&mut state, &ctx(user), &pay).unwrap();
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
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &BindingTx::Register {
                domain_key: DOMAIN,
                origin_app: origin.clone(),
                manifest_hash: [0x11; 32],
            },
        )
        .unwrap();
        let id = calc_binding_id(DOMAIN, &origin);
        let open = BindingTx::OpenIntent {
            app_binding_id: id,
            call_hash: [0x22; 32],
            value: 0,
            max_payment: 1_000,
            solver_fee_cap: 100,
            service_price: 200,
            origin_beneficiary: vec![0x33; 20],
            deadline_block: 0,
        };
        // No executor named for the domain yet: no intent can be served.
        assert!(execute_app_binding_tx(&mut state, &ctx(user), &open).is_err());
        execute_app_binding_tx(
            &mut state,
            &ctx(operator),
            &BindingTx::SetExecutor {
                domain_key: DOMAIN,
                executor: executor.clone(),
            },
        )
        .unwrap();
        let before = state.get_balance(&user);
        execute_app_binding_tx(&mut state, &ctx(user), &open).unwrap();
        assert_eq!(state.get_balance(&user), before - 1_000);
        let intent = state
            .settlement
            .app_binding
            .intents
            .values()
            .next()
            .unwrap()
            .clone();
        let rival = Address::from([0x07; 32]);
        state
            .registry
            .register(rival, crate::registry::role::roles::RELAYER, bond, epoch)
            .unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(rival),
            &BindingTx::Bid {
                intent_id: intent.intent_id,
                cost: 600,
                fee: 50,
            },
        )
        .unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(solver),
            &BindingTx::Bid {
                intent_id: intent.intent_id,
                cost: 400,
                fee: 50,
            },
        )
        .unwrap();
        assert!(execute_app_binding_tx(
            &mut state,
            &ctx(solver),
            &BindingTx::Award {
                intent_id: intent.intent_id,
                solver,
            }
        )
        .is_err());
        let before_award = state.settlement.app_binding.root();
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &BindingTx::Award {
                intent_id: intent.intent_id,
                solver,
            },
        )
        .unwrap();
        assert_eq!(
            state.settlement.app_binding.intents[&intent.intent_id].awarded_solver,
            Some(solver)
        );
        assert_ne!(before_award, state.settlement.app_binding.root());
        let restored: AppBindingRegistry =
            serde_json::from_str(&serde_json::to_string(&state.settlement.app_binding).unwrap())
                .unwrap();
        assert_eq!(restored.root(), state.settlement.app_binding.root());
        assert_eq!(
            restored.intents[&intent.intent_id].awarded_solver,
            Some(solver)
        );
        // Once a solver acts, a late cheaper offer cannot change the award.
        let late = Address::from([0x06; 32]);
        state
            .registry
            .register(late, crate::registry::role::roles::RELAYER, bond, epoch)
            .unwrap();
        assert!(execute_app_binding_tx(
            &mut state,
            &ctx(late),
            &BindingTx::Bid {
                intent_id: intent.intent_id,
                cost: 1,
                fee: 1
            }
        )
        .is_err());
        // An event from the right executor about another call pays nothing.
        let mut other = intent.clone();
        other.call_hash = [0x23; 32];
        let wrong = message(
            origin_emitter(&executor),
            Address::zero(),
            fulfilled_payload_hash(&other, &origin, solver),
            APP_BINDING_FULFILLED_KIND,
            intent.intent_id,
        );
        let evidence = anchored(&mut state, wrong);
        let fulfil = |evidence| BindingTx::Fulfill {
            intent_id: intent.intent_id,
            evidence,
        };
        assert!(execute_app_binding_tx(&mut state, &ctx(solver), &fulfil(evidence)).is_err());

        let right = message(
            origin_emitter(&executor),
            Address::zero(),
            fulfilled_payload_hash(&intent, &origin, solver),
            APP_BINDING_FULFILLED_KIND,
            intent.intent_id,
        );
        let evidence = anchored(&mut state, right);
        // A rival cannot reuse the public proof (or offer a higher-priced
        // proof of its own execution) after the owner chose another winner.
        assert!(
            execute_app_binding_tx(&mut state, &ctx(rival), &fulfil(evidence.clone())).is_err()
        );
        // The application payout is last after the solver credit. A full
        // recipient account must refuse BEFORE either the solver is paid or
        // the intent is removed, even when the external proof is valid.
        let app_mirror = mirror_account(id);
        state.add_balance(&app_mirror, u64::MAX);
        let before_refusal = state.settlement.app_binding.root();
        assert!(
            execute_app_binding_tx(&mut state, &ctx(solver), &fulfil(evidence.clone())).is_err()
        );
        assert_eq!(state.settlement.app_binding.root(), before_refusal);
        assert_eq!(state.get_balance(&solver), 0);
        assert!(state
            .settlement
            .app_binding
            .intents
            .contains_key(&intent.intent_id));
        state.get_or_create(&app_mirror).balance = 0;
        execute_app_binding_tx(&mut state, &ctx(solver), &fulfil(evidence)).unwrap();
        assert_eq!(state.get_balance(&solver), 450);
        assert_eq!(state.get_balance(&mirror_account(id)), 200);
        assert_eq!(state.get_balance(&user), before - 1_000 + 350);
        assert!(state.settlement.app_binding.intents.is_empty());
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
            .app_binding
            .register(DOMAIN, origin.clone(), [0x11; 32], 0)
            .unwrap();
        state
            .settlement
            .app_binding
            .executors
            .insert(DOMAIN, vec![0x77; 20]);
        let id = calc_binding_id(DOMAIN, &origin);
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &BindingTx::OpenIntent {
                app_binding_id: id,
                call_hash: [0x22; 32],
                value: 0,
                max_payment: 1_000,
                solver_fee_cap: 100,
                service_price: 0,
                origin_beneficiary: vec![0x33; 20],
                deadline_block: 600,
            },
        )
        .unwrap();
        let intent_id = *state.settlement.app_binding.intents.keys().next().unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(solver),
            &BindingTx::Bid {
                intent_id,
                cost: 100,
                fee: 10,
            },
        )
        .unwrap();
        let rival = Address::from([0x06; 32]);
        state
            .registry
            .register(rival, crate::registry::role::roles::RELAYER, bond, epoch)
            .unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(rival),
            &BindingTx::Bid {
                intent_id,
                cost: 200,
                fee: 10,
            },
        )
        .unwrap();
        let refund = BindingTx::Refund { intent_id };
        let mut unawarded = state.clone();
        unawarded.current_block_height = 601;
        execute_app_binding_tx(&mut unawarded, &ctx(user), &refund).unwrap();
        assert_eq!(
            unawarded
                .registry
                .get(&solver, crate::registry::role::roles::RELAYER)
                .unwrap()
                .stake,
            bond
        );
        assert_eq!(
            unawarded
                .registry
                .get(&rival, crate::registry::role::roles::RELAYER)
                .unwrap()
                .stake,
            bond
        );
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &BindingTx::Award { intent_id, solver },
        )
        .unwrap();
        assert!(execute_app_binding_tx(&mut state, &ctx(user), &refund).is_err());
        state.current_block_height = 601;
        let before = state.get_balance(&user);
        let registry_before = state.settlement.app_binding.root();
        let solver_stake_before = state
            .registry
            .get(&solver, crate::registry::role::roles::RELAYER)
            .unwrap()
            .stake;
        state.get_or_create(&user).balance = u64::MAX;
        assert!(execute_app_binding_tx(&mut state, &ctx(user), &refund).is_err());
        assert_eq!(state.settlement.app_binding.root(), registry_before);
        assert_eq!(
            state
                .registry
                .get(&solver, crate::registry::role::roles::RELAYER)
                .unwrap()
                .stake,
            solver_stake_before
        );
        assert!(state
            .settlement
            .app_binding
            .intents
            .contains_key(&intent_id));
        state.get_or_create(&user).balance = before;
        execute_app_binding_tx(&mut state, &ctx(user), &refund).unwrap();
        assert_eq!(state.get_balance(&user), before + 1_000);
        let stake = state
            .registry
            .get(&solver, crate::registry::role::roles::RELAYER)
            .unwrap()
            .stake;
        assert!(stake < bond, "the undelivered bid costs bond");
        assert_eq!(
            state
                .registry
                .get(&rival, crate::registry::role::roles::RELAYER)
                .unwrap()
                .stake,
            bond,
            "the unawarded bid must not be slashed"
        );
    }

    #[test]
    fn a_fee_share_goes_to_the_application_never_back_to_its_sender() {
        let operator = Address::from([0x01; 32]);
        let user = Address::from([0x03; 32]);
        let mut state = state_with_domain(operator);
        state
            .settlement
            .app_binding
            .register(DOMAIN, vec![0xAA; 20], [0x11; 32], 0)
            .unwrap();
        let id = calc_binding_id(DOMAIN, &[0xAA; 20]);
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
                    crate::settlement::domains::SettlementTx::AppBinding(Box::new(
                        BindingTx::Pay {
                            app_binding_id: id,
                            amount: 1,
                            memo_hash: [0u8; 32],
                            origin_recipient: vec![1],
                            target_chain_id: 0,
                            target_receiver: Vec::new(),
                        },
                    )),
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
        let mut testnet_payment = pay(user);
        testnet_payment.chain_id = crate::core::chain_config::Network::Testnet
            .chain_id()
            .value();
        assert_eq!(
            application_fee_recipient(&state, &testnet_payment),
            Some(mirror_account(id))
        );
        let mut mainnet_payment = pay(user);
        mainnet_payment.chain_id = crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value();
        assert_eq!(application_fee_recipient(&state, &mainnet_payment), None);
        state.settlement.domains.get_mut(DOMAIN).unwrap().status =
            crate::domain::DomainStatus::Frozen;
        assert_eq!(application_fee_recipient(&state, &pay(user)), None);
    }

    /// Cross-language known answers: contracts/test/Parity.t.sol pins the
    /// same values for `app_bindingExecutor` and `Budlumapp_bindingClaim`.
    #[test]
    fn event_payload_hashes_match_the_solidity_known_answers() {
        let intent = AppBindingIntent {
            intent_id: [0x11; 32],
            app_binding_id: [0u8; 32],
            owner: Address::zero(),
            call_hash: [0x33; 32],
            value: 7,
            max_payment: 0,
            solver_fee_cap: 0,
            service_price: 0,
            origin_beneficiary: vec![0x44; 20],
            deadline_block: 0,
            bids: Vec::new(),
            awarded_solver: None,
            // Not part of the fulfilment preimage: the snapshot binds which
            // emitter may prove the call, while the payload hash the origin
            // chain signs stays the cross-language known answer asserted below.
            executor: Vec::new(),
        };
        assert_eq!(
            hex::encode(fulfilled_payload_hash(
                &intent,
                &[0x22; 20],
                Address::from([0x55; 32])
            )),
            "6adf4090bb15ec7ee9af78d320f48e22c0eb09b68dd2a3a4ea36db9eeb0c5097"
        );
        assert_eq!(
            hex::encode(claim_payload_hash([0x66; 32], Address::from([0x77; 32]))),
            "df19fce601b54d83b5233db52f5c9d767af6e434f4839e9382aeae049349d7c1"
        );
    }

    /// An externally owned application claims with its own key. The
    /// signature was made with Foundry's `cast wallet sign` over
    /// `eoa_claim_hash(45262, app_id, [0x33; 32], 100)` by the key of
    /// 0x2c75..5c23.
    #[test]
    fn an_eoa_application_claims_with_its_personal_sign_signature() {
        const SIGNATURE: &str = "d988638ac25e6650eb787f5ccc329eecc9af09d0848904c3f88948628ac3afe335e456596a9c5234d20371a472d961555aeb9768a78961699233975f3e6998511c";
        let operator = Address::from([0x01; 32]);
        let registrant = Address::from([0x02; 32]);
        let mut state = state_with_domain(operator);
        state.add_balance(&registrant, 1_000_000);
        let eoa = hex::decode("2c7536e3605d9c16a7a3d7b1898e529396a65c23").unwrap();
        run_binding_tx(
            &mut state,
            &ctx(registrant),
            &BindingTx::Register {
                domain_key: DOMAIN,
                origin_app: eoa.clone(),
                manifest_hash: [0x11; 32],
            },
        )
        .unwrap();
        let id = calc_binding_id(DOMAIN, &eoa);
        assert_eq!(
            hex::encode(eoa_claim_hash(
                crate::core::transaction::DEFAULT_CHAIN_ID,
                id,
                Address::from([0x33; 32]),
                100
            )),
            "d3cd5b3cde66f6bc2a1e1daa7965c339c1deae7315987be22cd4cba175fdaebf"
        );
        let claim = BindingTx::ClaimBySignature {
            app_binding_id: id,
            payout: Address::from([0x33; 32]),
            valid_until_block: 100,
            signature: hex::decode(SIGNATURE).unwrap(),
        };
        run_binding_tx(&mut state, &ctx(registrant), &claim).expect("the key claims");
        assert_eq!(
            state.settlement.app_binding.get(&id).unwrap().owner,
            Address::from([0x33; 32])
        );
        assert!(
            run_binding_tx(&mut state, &ctx(registrant), &claim).is_err(),
            "each signature works once"
        );
        let other_payout = BindingTx::ClaimBySignature {
            app_binding_id: id,
            payout: Address::from([0x34; 32]),
            valid_until_block: 100,
            signature: hex::decode(SIGNATURE).unwrap(),
        };
        assert!(execute_app_binding_tx(&mut state, &ctx(registrant), &other_payout).is_err());
    }

    #[test]
    fn non_matching_origin_app_width_is_refused_before_escrow() {
        let operator = Address::from([0x01; 32]);
        let user = Address::from([0x03; 32]);
        let mut state = state_with_domain(operator);
        state.add_balance(&user, 10_000);
        // Register a 32-byte app before an executor exists, then set a 20-byte executor.
        let wide_app = vec![0xAA; 32];
        run_binding_tx(
            &mut state,
            &ctx(user),
            &BindingTx::Register {
                domain_key: DOMAIN,
                origin_app: wide_app.clone(),
                manifest_hash: [0x11; 32],
            },
        )
        .unwrap();
        run_binding_tx(
            &mut state,
            &ctx(operator),
            &BindingTx::SetExecutor {
                domain_key: DOMAIN,
                executor: vec![0x77; 20],
            },
        )
        .unwrap();
        let open = BindingTx::OpenIntent {
            app_binding_id: calc_binding_id(DOMAIN, &wide_app),
            call_hash: [0x22; 32],
            value: 0,
            max_payment: 1_000,
            solver_fee_cap: 100,
            service_price: 200,
            origin_beneficiary: vec![0x33; 20],
            deadline_block: 0,
        };
        assert!(
            run_binding_tx(&mut state, &ctx(user), &open).is_err(),
            "an intent whose app identifier width differs from the executor's must be refused"
        );
        // Registering a new mismatched-width app after the executor is set is refused too.
        assert!(run_binding_tx(
            &mut state,
            &ctx(user),
            &BindingTx::Register {
                domain_key: DOMAIN,
                origin_app: vec![0xBB; 32],
                manifest_hash: [0x11; 32],
            },
        )
        .is_err());
    }
    #[test]
    fn offchain_binding_verifier_binds_application_chain_and_receiver() {
        let payment = AppBindingPayment {
            payment_id: [0x11; 32],
            app_binding_id: [0x22; 32],
            payer: Address::from([0x33; 32]),
            recipient: Address::from([0x44; 32]),
            amount: 500,
            origin_recipient: vec![0x55; 20],
            memo_hash: [0x66; 32],
            paid_at_block: 10,
            target_chain_id: 8453,
            target_receiver: vec![0x77; 20],
        };
        let leaf = payment.leaf_hash();
        let proof = AppBindingPaymentProof {
            payment,
            path: crate::cross_domain::event_tree::MerkleProof {
                leaf,
                index: 0,
                siblings: Vec::new(),
            },
            opening: AppBindingRootOpening {
                payments_root: leaf,
                rest_hash: [0x88; 32],
            },
            header: crate::settlement::GlobalBlockHeader {
                version: 7,
                global_height: 15,
                previous_global_hash: [0u8; 32],
                chain_id: 45261,
                timestamp_ms: 1_000,
                domain_registry_root: [0u8; 32],
                domain_commitment_root: [0u8; 32],
                message_root: [0u8; 32],
                bridge_state_root: [0u8; 32],
                replay_nonce_root: [0u8; 32],
                proposer: None,
                settlement_finality_root: [0u8; 32],
                storage_root: None,
                ai_root: None,
                identity_root: None,
                checkpoint_height: 15,
                external_intake_root: None,
                app_binding_root: None,
                delegation_root: None,
                object_layer_root: None,
                proof_root: None,
                proven_height: 0,
            },
            block_height: 15,
            state_root: "00".repeat(32),
            state_root_body: None,
        };
        let cp = crate::light_client::VerifiedCheckpoint {
            height: 15,
            block_hash: "00".repeat(32),
            set_hash: "00".repeat(32),
            epoch: 0,
            state_root: "00".repeat(32),
        };
        assert_eq!(
            verify_app_binding_payment(&proof, &cp, [0x99; 32], 8453, &[0x77; 20]),
            Err(AppBindingProofError::Application)
        );
        assert_eq!(
            verify_app_binding_payment(&proof, &cp, [0x22; 32], 1, &[0x77; 20]),
            Err(AppBindingProofError::Receiver)
        );
        assert_eq!(
            verify_app_binding_payment(&proof, &cp, [0x22; 32], 8453, &[0x99; 20]),
            Err(AppBindingProofError::Receiver)
        );
    }

    #[test]
    fn app_binding_claim_claim_by_signature_and_fulfill_refuse_frozen_or_retired_domain() {
        let operator = Address::from([0x01; 32]);
        let registrant = Address::from([0x02; 32]);
        let user = Address::from([0x03; 32]);
        let solver = Address::from([0x04; 32]);
        let payout = Address::from([0x33; 32]);

        let mut state = state_with_domain(operator);
        let origin_app = vec![0xAB; 20];
        let id = calc_binding_id(DOMAIN, &origin_app);
        state.add_balance(&registrant, 1_000);
        state.add_balance(&user, 10_000);
        state.add_balance(&solver, 10_000);
        run_binding_tx(
            &mut state,
            &ctx(registrant),
            &BindingTx::Register {
                domain_key: DOMAIN,
                origin_app: origin_app.clone(),
                manifest_hash: [0x11; 32],
            },
        )
        .unwrap();
        let executor = vec![0xCD; 20];
        run_binding_tx(
            &mut state,
            &ctx(operator),
            &BindingTx::SetExecutor {
                domain_key: DOMAIN,
                executor: executor.clone(),
            },
        )
        .unwrap();

        let claim_msg = message(
            origin_emitter(&origin_app),
            payout,
            claim_payload_hash(id, payout),
            CLAIM_KIND,
            id,
        );
        let claim_ev = anchored(&mut state, claim_msg);

        // Create and award an intent while Active, then freeze the domain.
        let intent_tx = BindingTx::OpenIntent {
            app_binding_id: id,
            call_hash: [0x91; 32],
            value: 0,
            max_payment: 1_000,
            solver_fee_cap: 100,
            service_price: 200,
            origin_beneficiary: vec![0x33; 20],
            deadline_block: 600,
        };
        run_binding_tx(&mut state, &ctx(user), &intent_tx).unwrap();
        let stake = state.registry.params().min_stake;
        let relayer_role = crate::registry::role::roles::RELAYER;
        state
            .registry
            .register(solver, relayer_role, stake, 0)
            .unwrap();
        let intent = state
            .settlement
            .app_binding
            .intents
            .values()
            .next()
            .unwrap()
            .clone();
        let intent_id = intent.intent_id;
        run_binding_tx(
            &mut state,
            &ctx(solver),
            &BindingTx::Bid {
                intent_id,
                cost: 100,
                fee: 10,
            },
        )
        .unwrap();
        let award = execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &BindingTx::Award { intent_id, solver },
        );
        award.unwrap();
        let intent = state
            .settlement
            .app_binding
            .intents
            .get(&intent_id)
            .unwrap()
            .clone();
        let fulfill_msg = message(
            origin_emitter(&executor),
            solver,
            fulfilled_payload_hash(&intent, &origin_app, solver),
            FULFILLED_KIND,
            intent_id,
        );
        let fulfill_ev = anchored(&mut state, fulfill_msg);

        for status in [
            crate::domain::DomainStatus::Frozen,
            crate::domain::DomainStatus::Retired,
        ] {
            state.settlement.domains.set_status(DOMAIN, status).unwrap();
            assert!(run_binding_tx(
                &mut state,
                &ctx(registrant),
                &BindingTx::Claim {
                    app_binding_id: id,
                    payout,
                    evidence: claim_ev.clone(),
                },
            )
            .is_err());
            assert!(run_binding_tx(
                &mut state,
                &ctx(registrant),
                &BindingTx::ClaimBySignature {
                    app_binding_id: id,
                    payout,
                    valid_until_block: 50,
                    signature: vec![0u8; 65],
                },
            )
            .is_err());
            let pay_err = run_binding_tx(
                &mut state,
                &ctx(user),
                &BindingTx::Pay {
                    app_binding_id: id,
                    amount: 10,
                    memo_hash: [0x11; 32],
                    origin_recipient: vec![0x22; 20],
                    target_chain_id: 0,
                    target_receiver: Vec::new(),
                },
            )
            .unwrap_err();
            assert!(
                pay_err.to_string().contains("not active"),
                "Pay must refuse inactive domain: {pay_err}"
            );
            let open_err = run_binding_tx(
                &mut state,
                &ctx(user),
                &BindingTx::OpenIntent {
                    app_binding_id: id,
                    call_hash: [0x92; 32],
                    value: 0,
                    max_payment: 500,
                    solver_fee_cap: 50,
                    service_price: 50,
                    origin_beneficiary: vec![0x33; 20],
                    deadline_block: 720,
                },
            )
            .unwrap_err();
            assert!(
                open_err.to_string().contains("not active"),
                "OpenIntent must refuse inactive domain: {open_err}"
            );
            assert!(run_binding_tx(
                &mut state,
                &ctx(solver),
                &BindingTx::Fulfill {
                    intent_id,
                    evidence: fulfill_ev.clone(),
                },
            )
            .is_err());
        }

        // When an intent expires while the domain is Frozen/Retired, Refund
        // returns the user's escrow without slashing the awarded solver that
        // was forbidden from calling Fulfill.
        state.current_block_height = 601;
        let user_before = state.get_balance(&user);
        run_binding_tx(&mut state, &ctx(user), &BindingTx::Refund { intent_id }).unwrap();
        assert_eq!(state.get_balance(&user), user_before + 1_000);
        let reg = state
            .registry
            .get(&solver, relayer_role)
            .expect("solver registration remains");
        assert_eq!(
            reg.stake, stake,
            "solver bond must not be burned when domain was inactive"
        );

        state.settlement.domains.get_mut(DOMAIN).unwrap().status =
            crate::domain::DomainStatus::Active;

        // Short-window intent (< MIN_APP_BINDING_AWARD_WINDOW_BLOCKS remaining) cannot be awarded.
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &AppBindingTx::OpenIntent {
                app_binding_id: id,
                call_hash: [0x94; 32],
                value: 0,
                max_payment: 500,
                solver_fee_cap: 50,
                service_price: 50,
                origin_beneficiary: vec![0x33; 20],
                deadline_block: 1_000,
            },
        )
        .unwrap();
        let short_id = state
            .settlement
            .app_binding
            .intents
            .values()
            .find(|i| i.call_hash == [0x94; 32])
            .unwrap()
            .intent_id;
        execute_app_binding_tx(
            &mut state,
            &ctx(solver),
            &AppBindingTx::Bid {
                intent_id: short_id,
                cost: 50,
                fee: 10,
            },
        )
        .unwrap();
        assert!(
            execute_app_binding_tx(
                &mut state,
                &ctx(user),
                &AppBindingTx::Award {
                    intent_id: short_id,
                    solver,
                }
            )
            .is_err(),
            "Award with < MIN_APP_BINDING_AWARD_WINDOW_BLOCKS remaining must be refused"
        );

        // Unawarded intents must NOT pin executor rotation.
        execute_app_binding_tx(
            &mut state,
            &ctx(operator),
            &AppBindingTx::SetExecutor {
                domain_key: DOMAIN,
                executor: vec![0x87; 20],
            },
        )
        .expect("unawarded intents must not block SetExecutor");

        // Open an intent with >= 600 blocks remaining, bid, and award -> now rotation IS blocked.
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &AppBindingTx::OpenIntent {
                app_binding_id: id,
                call_hash: [0x93; 32],
                value: 0,
                max_payment: 500,
                solver_fee_cap: 50,
                service_price: 50,
                origin_beneficiary: vec![0x33; 20],
                deadline_block: 1_300,
            },
        )
        .unwrap();
        let awarded_id = state
            .settlement
            .app_binding
            .intents
            .values()
            .find(|i| i.call_hash == [0x93; 32])
            .unwrap()
            .intent_id;
        execute_app_binding_tx(
            &mut state,
            &ctx(solver),
            &AppBindingTx::Bid {
                intent_id: awarded_id,
                cost: 50,
                fee: 10,
            },
        )
        .unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &AppBindingTx::Award {
                intent_id: awarded_id,
                solver,
            },
        )
        .unwrap();
        // An awarded, live intent no longer pins rotation: the intent carries
        // the executor it was awarded against, so replacing the domain pointer
        // cannot strand the solver. The veto this replaces was reachable by any
        // RELAYER bond holder for the whole intent horizon, renewable at will.
        let snapshotted = state.settlement.app_binding.intents[&awarded_id]
            .executor
            .clone();
        assert!(
            !snapshotted.is_empty(),
            "an intent opened against a named executor must snapshot it"
        );
        execute_app_binding_tx(
            &mut state,
            &ctx(operator),
            &AppBindingTx::SetExecutor {
                domain_key: DOMAIN,
                executor: vec![0x88; 20],
            },
        )
        .expect("an awarded intent must not pin the domain executor");
        assert_eq!(
            state.settlement.app_binding.executors[&DOMAIN],
            vec![0x88; 20],
            "rotation writes the new pointer"
        );
        assert_eq!(
            state.settlement.app_binding.intents[&awarded_id].executor, snapshotted,
            "the open intent keeps the executor it was awarded against"
        );

        // The deterministic block-end sweep retires every intent past its
        // deadline and refunds each escrow, so stale rows never accumulate in
        // consensus state. Two are expired here: the short-window intent
        // (deadline 1_000) and the awarded one (deadline 1_300).
        state.current_block_height = 1_301;
        let user_before = state.get_balance(&user);
        let height = state.current_block_height;
        sweep_expired_intents(&mut state, height).unwrap();
        assert!(
            !state
                .settlement
                .app_binding
                .intents
                .contains_key(&awarded_id),
            "the expired awarded intent must be swept"
        );
        assert!(
            !state.settlement.app_binding.intents.contains_key(&short_id),
            "every intent past its deadline must be swept, not only the awarded one"
        );
        assert_eq!(
            state.get_balance(&user),
            user_before + 1_000,
            "the sweep refunds each expired intent's escrowed max_payment"
        );
    }
    #[test]
    fn owner_can_award_performing_solver_over_zero_value_bid_and_refuses_non_bidder() {
        let operator = Address::from([0x01; 32]);
        let user = Address::from([0x03; 32]);
        let solver = Address::from([0x05; 32]);
        let griefer = Address::from([0x06; 32]);
        let bystander = Address::from([0x07; 32]);
        let origin = vec![0xEE; 20];
        let mut state = state_with_domain(operator);
        state.add_balance(&user, 10_000);
        let bond = state.registry.params().min_stake;
        let epoch = state.epoch_index;
        for addr in [solver, griefer] {
            state
                .registry
                .register(addr, crate::registry::role::roles::RELAYER, bond, epoch)
                .unwrap();
        }
        state
            .settlement
            .app_binding
            .register(DOMAIN, origin.clone(), [0x11; 32], 0)
            .unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(operator),
            &AppBindingTx::SetExecutor {
                domain_key: DOMAIN,
                executor: vec![0x88; 20],
            },
        )
        .unwrap();
        let id = app_binding_id(DOMAIN, &origin);
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &AppBindingTx::OpenIntent {
                app_binding_id: id,
                call_hash: [0x95; 32],
                value: 0,
                max_payment: 1_000,
                solver_fee_cap: 100,
                service_price: 200,
                origin_beneficiary: vec![0x33; 20],
                deadline_block: 1_000,
            },
        )
        .unwrap();
        let intent_id = *state.settlement.app_binding.intents.keys().next().unwrap();
        // Griefer undercuts with a zero-value bid; real solver posts a nonzero offer.
        execute_app_binding_tx(
            &mut state,
            &ctx(griefer),
            &AppBindingTx::Bid {
                intent_id,
                cost: 0,
                fee: 0,
            },
        )
        .unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(solver),
            &AppBindingTx::Bid {
                intent_id,
                cost: 400,
                fee: 50,
            },
        )
        .unwrap();

        let non_bidder_err = execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &AppBindingTx::Award {
                intent_id,
                solver: bystander,
            },
        )
        .unwrap_err();
        assert!(
            non_bidder_err.to_string().contains("has not bid"),
            "{non_bidder_err}"
        );

        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &AppBindingTx::Award { intent_id, solver },
        )
        .unwrap();
        assert_eq!(
            state.settlement.app_binding.intents[&intent_id].awarded_solver,
            Some(solver)
        );
    }
    #[test]
    fn sweep_expired_intents_does_not_abort_when_awarded_solver_is_slashed_unbonding() {
        // Strix HIGH (PR #110): the block-end sweep aborted the whole block
        // transition when the awarded solver was already SlashedUnbonding,
        // because `is_slashable()` accepts that status but
        // `slash_role_only` refuses it. The intent row was removed, the
        // slash error propagated, the transition was discarded, and every
        // later block retried the same sweep and failed the same way.
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
            .app_binding
            .register(DOMAIN, origin.clone(), [0x11; 32], 0)
            .unwrap();
        state
            .settlement
            .app_binding
            .executors
            .insert(DOMAIN, vec![0x77; 20]);
        let id = app_binding_id(DOMAIN, &origin);
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &AppBindingTx::OpenIntent {
                app_binding_id: id,
                call_hash: [0x22; 32],
                value: 0,
                max_payment: 1_000,
                solver_fee_cap: 100,
                service_price: 0,
                origin_beneficiary: vec![0x33; 20],
                deadline_block: 600,
            },
        )
        .unwrap();
        let intent_id = *state.settlement.app_binding.intents.keys().next().unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(solver),
            &AppBindingTx::Bid {
                intent_id,
                cost: 100,
                fee: 10,
            },
        )
        .unwrap();
        execute_app_binding_tx(
            &mut state,
            &ctx(user),
            &AppBindingTx::Award { intent_id, solver },
        )
        .unwrap();
        // Put the awarded solver into SlashedUnbonding: slash for a
        // non-liveness condition, then begin unbonding.
        let ratio = state.registry.params().malicious_slash_ratio_fixed;
        state
            .registry
            .slash_role_only(
                solver,
                crate::registry::role::roles::RELAYER,
                crate::registry::permissionless::SlashingCondition::MaliciousBehaviour,
                ratio,
            )
            .unwrap();
        state
            .registry
            .begin_unbonding(solver, crate::registry::role::roles::RELAYER, epoch)
            .unwrap();
        assert!(matches!(
            state
                .registry
                .get(&solver, crate::registry::role::roles::RELAYER)
                .unwrap()
                .status,
            crate::registry::permissionless::MemberStatus::SlashedUnbonding { .. }
        ));
        let stake_after_slash = state
            .registry
            .get(&solver, crate::registry::role::roles::RELAYER)
            .unwrap()
            .stake;
        state.current_block_height = 601;
        let before = state.get_balance(&user);
        sweep_expired_intents(&mut state, 601)
            .expect("sweep must not abort for an already-slashed solver");
        assert!(
            !state
                .settlement
                .app_binding
                .intents
                .contains_key(&intent_id),
            "the expired intent must be retired"
        );
        assert_eq!(
            state.get_balance(&user),
            before + 1_000,
            "the owner escrow is refunded even though the solver was already slashed"
        );
        assert_eq!(
            state
                .registry
                .get(&solver, crate::registry::role::roles::RELAYER)
                .unwrap()
                .stake,
            stake_after_slash,
            "an already-slashed solver is not slashed a second time"
        );
    }
}
