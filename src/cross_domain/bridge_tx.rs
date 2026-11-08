//! Bridge writes as signed, in-block transactions.
//!
//! The bridge moves value between the domains Budlum settles: an asset is
//! registered against its home domain, a lock debits the owner and opens a
//! transfer, a mint credits the recipient against a verified lock event, a
//! burn debits the holder and emits the event the way back is proven with,
//! and an unlock returns the burned units to the owner. A relay proof does
//! the mint or the unlock through the universal relayer's pending queue.
//!
//! Every one of those writes used to happen outside a block, through
//! operator RPCs (`bud_registerBridgeAsset`, `bud_mintBridgeTransfer`,
//! `bud_burnBridgeTransferWithEvent`, `bud_unlockBridgeTransferVerified`,
//! `bud_submitRelayProof`) that changed `bridge_state`, the message
//! registry, the relayer ledger and balances on the serving node alone, and
//! persisted them beside the chain. This module
//! moves them into the block: [`execute_bridge_tx`] is the door the executor
//! applies them through, and the functions below are the only writers.
//!
//! Who may sign what:
//!
//! - registering an asset: the operator of the asset's home domain;
//! - a lock: the owner whose balance it debits;
//! - a mint, an unlock and a relay proof: any account holding an active
//!   RELAYER bond. The verdict comes from the proof against the committed
//!   event root, not from the carrier; the bond is what a carrier risks,
//!   and the mint's relayer fee is paid to it;
//! - a burn: the transfer's recipient, who holds the minted units.
//!
//! The door bodies are pub, exposed for the `Blockchain` test harness, which
//! drives the same code the door runs without building a signed block for
//! every bridge scenario.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::cross_domain::{
    AssetId, BridgeTransfer, CrossDomainMessage, DomainEvent, DomainEventKind, MerkleProof,
    MessageId, MessageKind,
};
use crate::domain::{DomainId, Hash32, POW_HEADER_CHAIN_ADAPTER};
use crate::settlement::{ProofVerificationError, SettlementProofVerifier, VerifiedDomainEvent};
use serde::{Deserialize, Serialize};

/// A domain event with the inclusion proof that places it under a committed
/// domain block. `expected_block_hash` is mandatory: without it a carrier
/// could pick any commitment at the `(domain, height, sequence)` tuple,
/// stale or equivocated ones included (security audit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenBridgeEvent {
    pub domain: DomainId,
    pub height: u64,
    pub sequence: u64,
    pub expected_block_hash: Hash32,
    pub event: DomainEvent,
    pub proof: MerkleProof,
}

/// A lock: the owner is the transaction sender.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockRequest {
    pub source_domain: DomainId,
    pub target_domain: DomainId,
    pub source_height: u64,
    pub event_index: u32,
    pub asset_id: AssetId,
    pub recipient: Address,
    pub amount: u64,
    pub expiry_height: u64,
}

/// A burn of the units held for transfer `message_id`: the burner is the
/// transfer's recipient.: the burner declares the
/// Ethereum destination here, at burn time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnRequest {
    pub message_id: MessageId,
    pub domain: DomainId,
    pub domain_height: u64,
    pub event_index: u32,
    pub expiry_height: u64,
    pub recipient_eth: [u8; 20],
}

/// One bridge write. The actor of every variant is `tx.from`, already
/// signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeTx {
    /// Register an asset against its home domain. The sender must operate
    /// that domain.
    RegisterAsset { asset_id: AssetId, domain: DomainId },
    /// Lock `amount` of the sender's balance for a transfer to `recipient`
    /// on `target_domain`.
    Lock(LockRequest),
    /// Mint against a verified lock event of the source domain. Boxed for
    /// the proof.
    Mint(Box<ProvenBridgeEvent>),
    /// Burn the units the sender holds for a transfer and emit the burn
    /// event, naming the Ethereum destination.
    BurnWithEvent(BurnRequest),
    /// Unlock against a verified burn event of the target domain. Boxed for
    /// the proof.
    Unlock(Box<ProvenBridgeEvent>),
    /// Relay a pending message with its inclusion proof against the source
    /// domain's committed event root.
    RelayProof {
        message_id: MessageId,
        source_domain: DomainId,
        proof: MerkleProof,
    },
}

/// Equality by wire encoding: the payloads carry event and proof types that
/// define no equality of their own, and two bridge writes are the same write
/// when they encode to the same bytes.
impl PartialEq for BridgeTx {
    fn eq(&self, other: &Self) -> bool {
        match (bincode::serialize(self), bincode::serialize(other)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for BridgeTx {}

/// What the executor hands the door.
pub struct BridgeTxContext {
    pub sender: Address,
    /// The fee the sender must still hold after the door has run.
    pub fee: u64,
    /// The height of the block being executed.
    pub height: u64,
}

/// Why a bridge transaction was refused. A refused transaction changes
/// nothing.
/// exposed for execute_bridge_tx: the executor's Bridge arm reports it by its message, not by name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BridgeTxError {
    #[error("only the operator of domain {0} may register its bridge assets")]
    NotTheOperator(DomainId),
    #[error("the carrier must hold an active RELAYER bond")]
    CarrierNotBonded,
    #[error("only the transfer's recipient may burn it")]
    BurnerIsNotSender,
    #[error("the sender holds {balance}, and the transfer plus the fee need {needed}")]
    Unfunded { needed: u64, balance: u64 },
    #[error("{0}")]
    Refused(String),
}

fn refused(e: impl ToString) -> BridgeTxError {
    BridgeTxError::Refused(e.to_string())
}

/// Verify that `event` is included under the commitment `(domain_id,
/// domain_height, sequence)` whose block hash is `expected_block_hash`.
/// Reads the settlement registries only.
///
/// # Errors
///
/// The verifier's refusal: an unknown commitment, a block hash mismatch, or
/// a proof that does not reach the committed event root.
pub fn verify_domain_event_proof(
    state: &AccountState,
    domain_id: DomainId,
    domain_height: u64,
    sequence: u64,
    expected_block_hash: Hash32,
    event: DomainEvent,
    proof: &MerkleProof,
) -> Result<VerifiedDomainEvent, ProofVerificationError> {
    SettlementProofVerifier::verify_event_from_registry(
        &state.settlement.commitments,
        domain_id,
        domain_height,
        sequence,
        expected_block_hash,
        event,
        proof,
    )
}

/// Register a cross-domain message the bridge emitted: the id must match
/// its preimage, source and target must differ, and an expiry must lie
/// ahead of `height`.
///
/// # Errors
///
/// The rule that failed, or the registry's refusal (a duplicate id).
pub fn register_bridge_message(
    state: &mut AccountState,
    message: CrossDomainMessage,
    height: u64,
) -> Result<(), String> {
    if !message.verify_id() {
        return Err(
            "Cross-domain message ID does not match canonical preimage (potential forgery)".into(),
        );
    }
    if message.source_domain == message.target_domain {
        return Err(format!(
            "Cross-domain message source and target domains must differ (both={})",
            message.source_domain
        ));
    }
    if message.expiry_height > 0 && height > message.expiry_height {
        return Err(format!(
            "Cross-domain message expired (expiry={}, current={height})",
            message.expiry_height
        ));
    }
    state.message_registry.insert(message)
}

/// Enqueue a bridge event for the universal relayer, through the same
/// pipeline the four-stage tests exercise.
pub fn enqueue_bridge_relay(
    state: &mut AccountState,
    source_event: &DomainEvent,
    message: &CrossDomainMessage,
    height: u64,
) {
    let mut stages = crate::cross_domain::bridge_relayer::BridgeRelayerPipeline::from_parts(
        &mut state.bridge_state,
        &mut state.settlement.relayer,
        &mut state.message_registry,
    );
    stages.enqueue_stage(source_event, message, height);
}

/// Register a bridge asset against an active, bridge-enabled domain.
///
/// # Errors
///
/// An unknown or closed domain, or the bridge state's refusal.
pub fn register_asset(
    state: &mut AccountState,
    asset_id: AssetId,
    domain: DomainId,
) -> Result<(), String> {
    let domain_ref = state
        .settlement
        .domains
        .get(domain)
        .ok_or_else(|| format!("Domain {domain} not found"))?;
    if !domain_ref.is_active() || !domain_ref.bridge_enabled {
        return Err(format!("Domain {domain} is not bridge-enabled"));
    }
    state
        .bridge_state
        .register_asset(asset_id, domain)
        .map_err(|e| e.to_string())
}

/// Lock `amount` of the owner's balance: open the transfer, register its
/// message, debit the owner and enqueue the relay. `reserve` is what the
/// owner must still hold afterwards (the transaction fee).
///
/// # Errors
///
/// A closed domain, a zero amount, a bad expiry, an unfunded owner, or the
/// bridge state's or message registry's refusal. A refusal changes nothing.
pub fn lock(
    state: &mut AccountState,
    owner: Address,
    params: &LockRequest,
    reserve: u64,
    height: u64,
) -> Result<(BridgeTransfer, DomainEvent), String> {
    for domain_id in [params.source_domain, params.target_domain] {
        let domain = state
            .settlement
            .domains
            .get(domain_id)
            .ok_or_else(|| format!("Domain {domain_id} not found"))?;
        if !domain.is_active() || !domain.bridge_enabled {
            return Err(format!("Domain {domain_id} is not bridge-enabled"));
        }
    }
    if params.source_domain == params.target_domain {
        return Err("Bridge source and target domains must differ".into());
    }
    if params.amount == 0 {
        return Err("Bridge transfer amount must be non-zero".into());
    }
    if params.expiry_height <= params.source_height {
        return Err("Bridge transfer expiry must be after source height".into());
    }
    // The owner is debited, so the balance is checked before the transfer
    // row exists: a refusal after the insert would leave a lock that never
    // debited anyone, and the expiry sweep would refund units never locked.
    let owner_balance = state.spendable_balance(&owner);
    let needed = params
        .amount
        .checked_add(reserve)
        .ok_or_else(|| "Bridge lock amount + fee overflows u64".to_string())?;
    if owner_balance < needed {
        return Err(format!(
            "Insufficient spendable balance for bridge lock: owner has {owner_balance}, needed {needed}"
        ));
    }
    // The message registry refusal rolls the row back,
    // so the order row -> registry -> debit leaves nothing behind.
    let bridge_before = state.bridge_state.clone();
    let result = state
        .bridge_state
        .lock(
            params.source_domain,
            params.target_domain,
            params.source_height,
            params.event_index,
            params.asset_id,
            owner,
            params.recipient,
            params.amount,
            params.expiry_height,
        )
        .map_err(|e| e.to_string())?;
    if let Some(message) = result.1.message.clone() {
        if let Err(e) = register_bridge_message(state, message, height) {
            state.bridge_state = bridge_before;
            return Err(e);
        }
    }
    let owner_account = state.get_or_create(&owner);
    owner_account.balance = owner_account.balance.saturating_sub(params.amount);
    state.mark_dirty(&owner);
    if let Some(message) = result.1.message.clone() {
        enqueue_bridge_relay(state, &result.1, &message, height);
    }
    Ok(result)
}

/// Mint against a verified lock event: the recipient receives the transfer
/// amount less the relayer fee, and `relayer` receives the fee. Both come
/// from the arriving asset, which is what lets a user bridge into Budlum
/// without holding any $BUD yet.
///
/// # Errors
///
/// A closed or unsettled source domain, a proof the verifier refuses, an
/// event that is not this transfer's lock, or the supply ceiling. Every
/// check runs before the bridge state moves.
pub fn mint_from_verified_event(
    state: &mut AccountState,
    proven: &ProvenBridgeEvent,
    relayer: Address,
    height: u64,
) -> Result<(), String> {
    let source_domain = proven.domain;
    let source_height = proven.height;
    // PoW mint is enabled only for domains whose commitments were verified
    // by the bounded header-chain adapter. Legacy self-declared PoW proofs
    // stay readable but can never authorize supply creation.
    let domain = state
        .settlement
        .domains
        .get(source_domain)
        .ok_or_else(|| format!("Unknown bridge source domain {source_domain}"))?;
    if matches!(domain.kind, crate::domain::types::ConsensusKind::PoW)
        && domain.finality_adapter != POW_HEADER_CHAIN_ADAPTER
    {
        return Err("Bridge mint from PoW domains requires pow-header-chain-v1 finality".into());
    }
    if !domain.bridge_enabled {
        return Err(format!("Bridge mint disabled for domain {source_domain}"));
    }
    // A finalized proof may arrive out of order and be staged in the
    // commitment registry; bridge verification may not consume it until the
    // domain's parent-linked chain has actually advanced past it.
    if source_height > domain.last_committed_height {
        return Err(format!(
            "Bridge source commitment at height {source_height} is not on the applied domain chain (tip {})",
            domain.last_committed_height
        ));
    }

    let verified = verify_domain_event_proof(
        state,
        source_domain,
        source_height,
        proven.sequence,
        proven.expected_block_hash,
        proven.event.clone(),
        &proven.proof,
    )
    .map_err(|e| e.to_string())?;

    if verified.event.kind != DomainEventKind::BridgeLocked {
        return Err("Verified event is not a bridge lock event".into());
    }
    let verified_event_hash = verified.event.leaf_hash();
    let message = verified
        .event
        .message
        .clone()
        .ok_or_else(|| "Verified bridge lock event is missing message".to_string())?;
    if message.kind != MessageKind::BridgeLock {
        return Err("Verified event message is not a bridge lock message".into());
    }
    if verified.event.payload_hash != message.payload_hash {
        return Err("Verified bridge event payload hash mismatch".into());
    }
    if let Some(expected_event_hash) = state.bridge_state.source_event_hash(&message.message_id) {
        if expected_event_hash != verified_event_hash {
            return Err("Verified bridge source event hash mismatch".into());
        }
    }

    // Amounts and the ceiling are settled before the bridge state moves:
    // after `mint` the replay id is spent and the transfer reads as minted,
    // so a refusal there would consume the lock and credit nothing.
    let transfer = state
        .bridge_state
        .get_transfer(&message.message_id)
        .ok_or_else(|| "Unknown bridge transfer for mint".to_string())?
        .clone();
    let params = *state.registry.params();
    let (final_amount, fee) = crate::cross_domain::bridge::split_bridge_fee(
        transfer.amount,
        params.bridge_relayer_fee_ppm,
        params.bridge_relayer_min_fee,
    )
    .map_err(|e| e.to_string())?;
    let minted = final_amount
        .get()
        .checked_add(fee.get())
        .ok_or_else(|| "Bridge amount exceeds maximum representable balance".to_string())?;
    state
        .ensure_mint_headroom(minted)
        .map_err(|e| format!("Bridge mint: {e}"))?;
    ensure_relay_credits_fit(
        state,
        (transfer.recipient, final_amount.get()),
        (relayer, fee.get()),
    )?;

    state
        .bridge_state
        .mint(&message, height)
        .map_err(|e| e.to_string())?;
    // The supply-creating path: the on-chain counterpart of the asset
    // arriving from the bridge is minted here, both legs under the fixed
    // ceiling.
    state
        .try_mint_balance(&transfer.recipient, final_amount.get())
        .map_err(|e| format!("Bridge mint (recipient): {e}"))?;
    state
        .try_mint_balance(&relayer, fee.get())
        .map_err(|e| format!("Bridge mint fee (relayer): {e}"))
}

/// Burn the units the transfer's recipient holds and emit the burn event.
/// `reserve` is what the burner must still hold afterwards (the fee).
///
/// # Errors
///
/// An unknown transfer, an unfunded burner, or the bridge state's or
/// message registry's refusal. A refusal changes nothing.
pub fn burn_with_event(
    state: &mut AccountState,
    request: &BurnRequest,
    reserve: u64,
    height: u64,
) -> Result<DomainEvent, String> {
    let message_id = request.message_id;
    // Burn is the debit half of mint. The recipient
    // holds what the mint credited to it - the amount less the relayer fee -
    // so that is what the burn takes back before the row flips.
    let transfer = state
        .bridge_state
        .get_transfer(&message_id)
        .cloned()
        .ok_or_else(|| "Unknown bridge transfer".to_string())?;
    let params = *state.registry.params();
    let (held, _relayer_fee) = crate::cross_domain::bridge::split_bridge_fee(
        transfer.amount,
        params.bridge_relayer_fee_ppm,
        params.bridge_relayer_min_fee,
    )
    .map_err(|e| e.to_string())?;
    let amount = held.get();
    let burner = transfer.recipient;
    let burner_balance = state.spendable_balance(&burner);
    let needed = amount
        .checked_add(reserve)
        .ok_or_else(|| "Bridge burn amount + fee overflows u64".to_string())?;
    if burner_balance < needed {
        return Err(format!(
            "Insufficient spendable balance for bridge burn: burner has {burner_balance}, needed {needed}"
        ));
    }
    let bridge_before = state.bridge_state.clone();
    let event = state
        .bridge_state
        .burn_with_event(
            message_id,
            request.domain,
            request.domain_height,
            request.event_index,
            request.expiry_height,
            request.recipient_eth,
        )
        .map_err(|e| e.to_string())?;
    if let Some(message) = event.message.clone() {
        if let Err(e) = register_bridge_message(state, message, height) {
            state.bridge_state = bridge_before;
            return Err(e);
        }
    }
    let burner_account = state.get_or_create(&burner);
    burner_account.balance = burner_account.balance.saturating_sub(amount);
    state.mark_dirty(&burner);
    state.bridge_state.record_burn_debit(&message_id, held);
    if let Some(message) = event.message.clone() {
        enqueue_bridge_relay(state, &event, &message, height);
    }
    Ok(event)
}

/// Unlock against a verified burn event: the owner receives back exactly
/// the units the burn debited.
///
/// # Errors
///
/// A proof the verifier refuses, an event that is not this transfer's
/// burn, a transfer with no recorded debit, or a balance overflow. Every
/// check runs before the bridge state moves.
pub fn unlock_from_verified_event(
    state: &mut AccountState,
    proven: &ProvenBridgeEvent,
    height: u64,
) -> Result<(), String> {
    let verified = verify_domain_event_proof(
        state,
        proven.domain,
        proven.height,
        proven.sequence,
        proven.expected_block_hash,
        proven.event.clone(),
        &proven.proof,
    )
    .map_err(|e| e.to_string())?;

    if verified.event.kind != DomainEventKind::BridgeBurned {
        return Err("Verified event is not a bridge burn event".into());
    }
    let message = verified
        .event
        .message
        .clone()
        .ok_or_else(|| "Verified bridge burn event is missing message".to_string())?;
    if message.kind != MessageKind::BridgeBurn {
        return Err("Verified event message is not a bridge burn message".into());
    }
    if !message.verify_id() {
        return Err("Verified bridge burn message id is invalid".into());
    }
    if verified.event.payload_hash != message.payload_hash {
        return Err("Verified bridge burn event payload hash mismatch".into());
    }

    let transfer_id = message
        .correlation_id
        .ok_or_else(|| "Verified bridge burn message is missing correlation id".to_string())?;
    let transfer = state
        .bridge_state
        .transfer(&transfer_id)
        .ok_or_else(|| "Unknown bridge transfer".to_string())?;
    crate::cross_domain::bridge::check_burn_matches_lock_domain(
        transfer.source_domain,
        message.target_domain,
    )
    .map_err(|e| e.to_string())?;
    if transfer.target_domain != message.source_domain {
        return Err("Verified bridge burn source domain mismatch".into());
    }
    if transfer.source_domain != message.target_domain {
        return Err("Verified bridge burn target domain mismatch".into());
    }
    if transfer.recipient != message.sender {
        return Err("Verified bridge burn sender mismatch".into());
    }
    if transfer.owner != message.recipient {
        return Err("Verified bridge burn recipient mismatch".into());
    }
    // The burn payload commits the Ethereum destination.
    let expected_payload_hash = match transfer.recipient_eth {
        Some(recipient_eth) => crate::cross_domain::bridge::bridge_burn_payload_hash(
            transfer.asset_id,
            transfer.amount.get(),
            &recipient_eth,
        ),
        None => crate::cross_domain::bridge::bridge_payload_hash(
            transfer.asset_id,
            transfer.amount.get(),
        ),
    };
    if message.payload_hash != expected_payload_hash {
        return Err("Verified bridge burn payload does not match transfer".into());
    }
    // Credit the exact units the burn debited, never a fresh split from
    // live fee parameters.
    if transfer.burned_amount == 0 {
        return Err("Bridge burn recorded no debit for this transfer".into());
    }
    let returned = transfer.burned_amount;
    let owner = transfer.owner;
    state
        .get_balance(&owner)
        .checked_add(returned)
        .ok_or_else(|| "Bridge unlock (owner credit) would overflow".to_string())?;

    state
        .bridge_state
        .unlock(transfer_id, message.source_domain, height)
        .map_err(|e| e.to_string())?;
    state
        .try_add_balance(&owner, returned)
        .map_err(|e| format!("Bridge unlock (owner credit): {e}"))
}

/// Relay a pending message: verify the proof against the source domain's
/// committed event root, record the relay, then mint or unlock.
///
/// # Errors
///
/// No pending relay, no committed event root, the relayer's refusal, or the
/// bridge effect's refusal. A refusal changes nothing.
pub fn submit_relay_proof(
    state: &mut AccountState,
    message_id: MessageId,
    relayer: Address,
    proof: &MerkleProof,
    source_domain: DomainId,
    height: u64,
) -> Result<CrossDomainMessage, String> {
    // The relay ledger only records relays that already completed, so it
    // cannot authenticate a source event: the committed event root of the
    // height the event was emitted at is the root of trust.
    let event_tree_root = {
        let pending = state
            .settlement
            .relayer
            .pending_relay(&message_id)
            .ok_or_else(|| format!("no pending relay for message {}", hex::encode(message_id)))?;
        let source_height = pending.source_event.domain_height;
        let commitment = state
            .settlement
            .commitments
            .find_by_height(source_domain, source_height)
            .ok_or_else(|| {
                format!(
                    "No committed event root for domain {source_domain} at height {source_height}"
                )
            })?;
        // The root is the root of trust only when the commitment's finality
        // proof binds it. A PoS or BFT certificate signs the checkpoint hash
        // and nothing else, so under one of those the event root is the
        // submitter's claim and a relay proven against it would mint from a
        // message the source domain never emitted.
        if !crate::settlement::domains::CommitmentAttestation::for_kind(&commitment.consensus_kind)
            .event_root
        {
            return Err(format!(
                "domain {source_domain} height {source_height}: event root is not bound by the \
                 commitment's finality proof"
            ));
        }
        commitment.event_root
    };
    // The ledger record is written inside `process_relay`; when the bridge
    // effect refuses afterwards, the relayer is put back as it was.
    let relayer_before = state.settlement.relayer.clone();
    let message = state
        .settlement
        .relayer
        .process_relay(
            message_id,
            relayer,
            proof,
            source_domain,
            event_tree_root,
            height,
        )
        .map_err(|e| e.to_string())?;
    if let Err(e) = apply_relay_effects(state, &message, relayer, height) {
        state.settlement.relayer = relayer_before;
        return Err(e);
    }
    Ok(message)
}

/// Bridge state change and credits for a relayed message. Every check that
/// can fail runs before the first mutation.
fn apply_relay_effects(
    state: &mut AccountState,
    message: &CrossDomainMessage,
    relayer: Address,
    height: u64,
) -> Result<(), String> {
    match message.kind {
        MessageKind::BridgeLock => {
            let transfer = state
                .bridge_state
                .get_transfer(&message.message_id)
                .ok_or_else(|| "Unknown bridge transfer for mint".to_string())?
                .clone();
            let params = *state.registry.params();
            let (final_amount, fee) = crate::cross_domain::bridge::split_bridge_fee(
                transfer.amount,
                params.bridge_relayer_fee_ppm,
                params.bridge_relayer_min_fee,
            )
            .map_err(|e| e.to_string())?;
            let minted = final_amount
                .get()
                .checked_add(fee.get())
                .ok_or_else(|| "Bridge amount exceeds maximum representable balance".to_string())?;
            state
                .ensure_mint_headroom(minted)
                .map_err(|e| format!("Bridge relay mint: {e}"))?;
            ensure_relay_credits_fit(
                state,
                (transfer.recipient, final_amount.get()),
                (relayer, fee.get()),
            )?;
            state
                .bridge_state
                .mint(message, height)
                .map_err(|e| e.to_string())?;
            state
                .try_mint_balance(&transfer.recipient, final_amount.get())
                .map_err(|e| format!("Bridge relay mint (recipient): {e}"))?;
            state
                .try_mint_balance(&relayer, fee.get())
                .map_err(|e| format!("Bridge relay mint fee (relayer): {e}"))?;
        }
        MessageKind::BridgeBurn => {
            // The burn message has its own id; the transfer lives under the
            // lock message id the burn correlates to, so the correlation id
            // is mandatory.
            let transfer_id = message.correlation_id.ok_or_else(|| {
                "Bridge burn message missing correlation_id (required to identify the original lock transfer)".to_string()
            })?;
            let transfer = state
                .bridge_state
                .get_transfer(&transfer_id)
                .ok_or_else(|| "Unknown bridge transfer".to_string())?
                .clone();
            crate::cross_domain::bridge::check_burn_matches_lock_domain(
                transfer.source_domain,
                message.target_domain,
            )
            .map_err(|e| e.to_string())?;
            if transfer.burned_amount == 0 {
                return Err("Bridge burn recorded no debit for this transfer".into());
            }
            let returned = transfer.burned_amount;
            ensure_relay_credits_fit(state, (transfer.owner, returned), (relayer, 0))?;
            state
                .bridge_state
                .unlock(transfer_id, message.source_domain, height)
                .map_err(|e| e.to_string())?;
            state
                .try_add_balance(&transfer.owner, returned)
                .map_err(|e| format!("Bridge relay unlock overflow (owner): {e}"))?;
        }
        _ => {
            return Err(format!(
                "Unsupported relay message kind: {:?}",
                message.kind
            ));
        }
    }
    Ok(())
}

/// Check that two credits fit in their balances. When both go to the same
/// account the two amounts are added first.
fn ensure_relay_credits_fit(
    state: &AccountState,
    first: (Address, u64),
    second: (Address, u64),
) -> Result<(), String> {
    let overflow = || "Bridge relay credit would overflow an account balance".to_string();
    if first.0 == second.0 {
        state
            .get_balance(&first.0)
            .checked_add(first.1)
            .and_then(|total| total.checked_add(second.1))
            .ok_or_else(overflow)?;
    } else {
        state
            .get_balance(&first.0)
            .checked_add(first.1)
            .ok_or_else(overflow)?;
        state
            .get_balance(&second.0)
            .checked_add(second.1)
            .ok_or_else(overflow)?;
    }
    Ok(())
}

fn ensure_carrier(state: &AccountState, sender: &Address) -> Result<(), BridgeTxError> {
    if state
        .registry
        .is_active(sender, crate::registry::role::roles::RELAYER)
    {
        Ok(())
    } else {
        Err(BridgeTxError::CarrierNotBonded)
    }
}

/// Apply one bridge write to `state`.
///
/// # Errors
///
/// The [`BridgeTxError`] that names the failed check.
pub fn execute_bridge_tx(
    state: &mut AccountState,
    ctx: &BridgeTxContext,
    tx: &BridgeTx,
) -> Result<(), BridgeTxError> {
    match tx {
        BridgeTx::RegisterAsset { asset_id, domain } => {
            let operator = state
                .settlement
                .domains
                .get(*domain)
                .ok_or_else(|| refused(format!("Domain {domain} not found")))?
                .operator;
            if operator != Some(ctx.sender) {
                return Err(BridgeTxError::NotTheOperator(*domain));
            }
            register_asset(state, *asset_id, *domain).map_err(refused)
        }
        BridgeTx::Lock(request) => {
            let balance = state.spendable_balance(&ctx.sender);
            let needed = request
                .amount
                .checked_add(ctx.fee)
                .ok_or_else(|| refused("Bridge lock amount + fee overflows u64"))?;
            if balance < needed {
                return Err(BridgeTxError::Unfunded { needed, balance });
            }
            lock(state, ctx.sender, request, ctx.fee, ctx.height)
                .map(|_| ())
                .map_err(refused)
        }
        BridgeTx::Mint(proven) => {
            ensure_carrier(state, &ctx.sender)?;
            mint_from_verified_event(state, proven, ctx.sender, ctx.height).map_err(refused)
        }
        BridgeTx::BurnWithEvent(request) => {
            let recipient = state
                .bridge_state
                .get_transfer(&request.message_id)
                .ok_or_else(|| refused("Unknown bridge transfer"))?
                .recipient;
            if recipient != ctx.sender {
                return Err(BridgeTxError::BurnerIsNotSender);
            }
            burn_with_event(state, request, ctx.fee, ctx.height)
                .map(|_| ())
                .map_err(refused)
        }
        BridgeTx::Unlock(proven) => {
            ensure_carrier(state, &ctx.sender)?;
            unlock_from_verified_event(state, proven, ctx.height).map_err(refused)
        }
        BridgeTx::RelayProof {
            message_id,
            source_domain,
            proof,
        } => {
            ensure_carrier(state, &ctx.sender)?;
            submit_relay_proof(
                state,
                *message_id,
                ctx.sender,
                proof,
                *source_domain,
                ctx.height,
            )
            .map(|_| ())
            .map_err(refused)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::plugin::default_domain;
    use crate::domain::ConsensusKind;

    const FEE: u64 = 3;
    const ASSET: AssetId = AssetId([0xA5; 32]);

    fn ctx(sender: Address) -> BridgeTxContext {
        BridgeTxContext {
            sender,
            fee: FEE,
            height: 5,
        }
    }

    /// A state with two bridge-enabled domains (1 and 2) and the asset
    /// registered against domain 1.
    fn bridged() -> (AccountState, Address) {
        let mut state = AccountState::new();
        let pow = default_domain(1, ConsensusKind::PoW, 45262, POW_HEADER_CHAIN_ADAPTER, 1);
        let operator = pow.operator.expect("default domains name an operator");
        crate::settlement::domains::register_domain(&mut state, pow).unwrap();
        crate::settlement::domains::register_domain(
            &mut state,
            default_domain(2, ConsensusKind::PoS, 1338, "pos-qc-finality", 0),
        )
        .unwrap();
        register_asset(&mut state, ASSET, 1).unwrap();
        (state, operator)
    }

    fn lock_request(amount: u64) -> LockRequest {
        LockRequest {
            source_domain: 1,
            target_domain: 2,
            source_height: 5,
            event_index: 0,
            asset_id: ASSET,
            recipient: Address::from([0x22; 32]),
            amount,
            expiry_height: 500,
        }
    }

    fn proven() -> ProvenBridgeEvent {
        ProvenBridgeEvent {
            domain: 1,
            height: 1,
            sequence: 0,
            expected_block_hash: [1u8; 32],
            event: DomainEvent {
                domain_id: 1,
                domain_height: 1,
                event_index: 0,
                kind: DomainEventKind::BridgeLocked,
                emitter: Address::from([0x11; 32]),
                message: None,
                payload_hash: [2u8; 32],
            },
            proof: MerkleProof {
                leaf: [3u8; 32],
                index: 0,
                siblings: vec![],
            },
        }
    }

    #[test]
    fn only_the_home_domain_operator_registers_an_asset() {
        let (mut state, operator) = bridged();
        let stranger = Address::from([0xEE; 32]);
        let tx = BridgeTx::RegisterAsset {
            asset_id: AssetId([0xB6; 32]),
            domain: 1,
        };
        assert_eq!(
            execute_bridge_tx(&mut state, &ctx(stranger), &tx).unwrap_err(),
            BridgeTxError::NotTheOperator(1)
        );
        let root_before = state.bridge_state.root();
        execute_bridge_tx(&mut state, &ctx(operator), &tx).unwrap();
        assert_ne!(state.bridge_state.root(), root_before);
    }

    #[test]
    fn a_lock_debits_the_sender_registers_its_message_and_enqueues_the_relay() {
        let (mut state, _) = bridged();
        let owner = Address::from([0x33; 32]);
        state.add_balance(&owner, 1_000 + FEE);
        let messages_before = state.message_registry.root();
        execute_bridge_tx(
            &mut state,
            &ctx(owner),
            &BridgeTx::Lock(lock_request(1_000)),
        )
        .unwrap();
        // The fee stays for the executor to take.
        assert_eq!(state.get_balance(&owner), FEE);
        assert_ne!(state.message_registry.root(), messages_before);
        assert_eq!(state.settlement.relayer.pending_count(), 1);
    }

    #[test]
    fn an_unfunded_lock_changes_nothing() {
        let (mut state, _) = bridged();
        let owner = Address::from([0x33; 32]);
        state.add_balance(&owner, 1_000);
        let bridge_before = state.bridge_state.root();
        let settlement_before = state.settlement.root();
        let err = execute_bridge_tx(
            &mut state,
            &ctx(owner),
            &BridgeTx::Lock(lock_request(1_000)),
        )
        .unwrap_err();
        assert!(matches!(err, BridgeTxError::Unfunded { .. }));
        assert_eq!(state.get_balance(&owner), 1_000);
        assert_eq!(state.bridge_state.root(), bridge_before);
        assert_eq!(state.settlement.root(), settlement_before);
    }

    #[test]
    fn only_the_transfer_recipient_burns_it() {
        let (mut state, _) = bridged();
        let owner = Address::from([0x33; 32]);
        state.add_balance(&owner, 1_000 + FEE);
        let (transfer, _) = lock(&mut state, owner, &lock_request(1_000), FEE, 5).unwrap();
        let burn = BridgeTx::BurnWithEvent(BurnRequest {
            message_id: transfer.message_id,
            domain: 2,
            domain_height: 6,
            event_index: 0,
            expiry_height: 600,
            recipient_eth: [7u8; 20],
        });
        assert_eq!(
            execute_bridge_tx(&mut state, &ctx(owner), &burn).unwrap_err(),
            BridgeTxError::BurnerIsNotSender
        );
    }

    #[test]
    fn a_carrier_without_a_relayer_bond_is_refused_before_any_check() {
        let (mut state, _) = bridged();
        let carrier = Address::from([0xCA; 32]);
        state.add_balance(&carrier, 1_000_000);
        let root_before = state.settlement.root();
        for tx in [
            BridgeTx::Mint(Box::new(proven())),
            BridgeTx::Unlock(Box::new(proven())),
            BridgeTx::RelayProof {
                message_id: [9u8; 32],
                source_domain: 1,
                proof: proven().proof,
            },
        ] {
            assert_eq!(
                execute_bridge_tx(&mut state, &ctx(carrier), &tx).unwrap_err(),
                BridgeTxError::CarrierNotBonded
            );
        }
        assert_eq!(state.settlement.root(), root_before);
    }

    #[test]
    fn the_relayer_queue_is_in_the_settlement_root() {
        let (mut state, _) = bridged();
        let owner = Address::from([0x33; 32]);
        state.add_balance(&owner, 1_000);
        let root_before = state.settlement.root();
        lock(&mut state, owner, &lock_request(1_000), 0, 5).unwrap();
        assert_ne!(
            state.settlement.root(),
            root_before,
            "a pending relay must move the settlement root"
        );
    }

    #[test]
    fn bridge_lock_refuses_vesting_locked_balance() {
        let (mut state, _) = bridged();
        let team = Address::from([0x77; 32]);
        state.add_balance(&team, 5_000);
        state.team_vesting = Some((
            team,
            crate::tokenomics::VestingSchedule {
                total: 5_000,
                start_epoch: 0,
                cliff_epochs: 10,
                duration_epochs: 100,
            },
        ));
        assert_eq!(state.spendable_balance(&team), 0);

        let err = execute_bridge_tx(
            &mut state,
            &ctx(team),
            &BridgeTx::Lock(lock_request(1_000)),
        )
        .unwrap_err();
        assert!(matches!(err, BridgeTxError::Unfunded { .. }));
        let req = lock_request(1_000);
        let direct = lock(&mut state, team, &req, FEE, 5);
        assert!(direct.is_err());
    }

    #[test]
    fn bridge_e2e_lock_mint_burn_unlock() {
        use crate::cross_domain::event_tree::DomainEventTree;
        use crate::domain::types::DomainCommitment;
        use crate::registry::role::roles::RELAYER;
        use crate::settlement::domains::accept_verified_commitment;

        let mut state = AccountState::new();
        let d10 = default_domain(10, ConsensusKind::PoW, 45262, POW_HEADER_CHAIN_ADAPTER, 1);
        let d11 = default_domain(11, ConsensusKind::PoW, 45263, POW_HEADER_CHAIN_ADAPTER, 1);
        crate::settlement::domains::register_domain(&mut state, d10).unwrap();
        crate::settlement::domains::register_domain(&mut state, d11).unwrap();
        register_asset(&mut state, ASSET, 10).unwrap();

        let owner = Address::from([0x41; 32]);
        let recipient = Address::from([0x22; 32]);
        let carrier = Address::from([0xCA; 32]);
        let min_stake = state.registry.params().min_stake;
        state.add_balance(&owner, 10_000 + FEE);
        state.add_balance(&recipient, FEE);
        state.add_balance(&carrier, min_stake.saturating_add(1_000));
        state
            .registry
            .register(carrier, RELAYER, min_stake, 0)
            .unwrap();

        // 1. Lock 1_000 on domain 10 -> domain 11 at domain_height 1.
        let lock_req = LockRequest {
            source_domain: 10,
            target_domain: 11,
            source_height: 1,
            event_index: 0,
            asset_id: ASSET,
            recipient,
            amount: 1_000,
            expiry_height: 500,
        };
        let locked = lock(&mut state, owner, &lock_req, FEE, 1).unwrap();
        let lock_event = locked.1;
        let lock_id = lock_event.message.as_ref().unwrap().message_id;
        assert_eq!(state.get_balance(&owner), 9_000 + FEE);

        // Anchor domain 10 commitment at height 1 with lock_event in its tree.
        let mut d10_tree = DomainEventTree::new();
        let d10_idx = d10_tree.push(lock_event.clone());
        let d10_proof = d10_tree.proof(d10_idx).unwrap();
        let d10_hash = [0xD1; 32];
        let d10_comm = DomainCommitment {
            domain_id: 10,
            domain_height: 1,
            domain_block_hash: d10_hash,
            parent_domain_block_hash: [0u8; 32],
            state_root: [0x11; 32],
            tx_root: [0u8; 32],
            event_root: d10_tree.root(),
            validator_set_hash: [0u8; 32],
            consensus_kind: ConsensusKind::PoW,
            finality_proof_hash: [0x22; 32],
            timestamp_ms: 1_000,
            sequence: 0,
            producer: None,
            state_updates: vec![],
        };
        accept_verified_commitment(&mut state, d10_comm).unwrap();

        // 2. Mint via execute_bridge_tx on target domain.
        let proven_lock = ProvenBridgeEvent {
            domain: 10,
            height: 1,
            sequence: 0,
            expected_block_hash: d10_hash,
            event: lock_event,
            proof: d10_proof,
        };
        execute_bridge_tx(
            &mut state,
            &ctx(carrier),
            &BridgeTx::Mint(Box::new(proven_lock)),
        )
        .unwrap();
        let minted_balance = state.get_balance(&recipient) - FEE;
        assert!(minted_balance > 0 && minted_balance <= 1_000);

        // 3. Burn on domain 11 at domain_height 1 naming an Ethereum destination.
        let burn_req = BurnRequest {
            message_id: lock_id,
            domain: 11,
            domain_height: 1,
            event_index: 0,
            expiry_height: 600,
            recipient_eth: [0xAB; 20],
        };
        let burn_event = burn_with_event(&mut state, &burn_req, FEE, 2).unwrap();
        assert_eq!(state.get_balance(&recipient), FEE);

        // Anchor domain 11 commitment at height 1 with burn_event in its tree.
        let mut d11_tree = DomainEventTree::new();
        let d11_idx = d11_tree.push(burn_event.clone());
        let d11_proof = d11_tree.proof(d11_idx).unwrap();
        let d11_hash = [0xD2; 32];
        let d11_comm = DomainCommitment {
            domain_id: 11,
            domain_height: 1,
            domain_block_hash: d11_hash,
            parent_domain_block_hash: [0u8; 32],
            state_root: [0x33; 32],
            tx_root: [0u8; 32],
            event_root: d11_tree.root(),
            validator_set_hash: [0u8; 32],
            consensus_kind: ConsensusKind::PoW,
            finality_proof_hash: [0x44; 32],
            timestamp_ms: 2_000,
            sequence: 0,
            producer: None,
            state_updates: vec![],
        };
        accept_verified_commitment(&mut state, d11_comm).unwrap();

        // 4. Unlock back to owner on source domain.
        let proven_burn = ProvenBridgeEvent {
            domain: 11,
            height: 1,
            sequence: 0,
            expected_block_hash: d11_hash,
            event: burn_event,
            proof: d11_proof,
        };
        execute_bridge_tx(
            &mut state,
            &ctx(carrier),
            &BridgeTx::Unlock(Box::new(proven_burn)),
        )
        .unwrap();
        assert_eq!(state.get_balance(&owner), 9_000 + FEE + minted_balance);
    }
}
