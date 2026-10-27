//! WIRING: wired - `SettlementTx::RelayerIntent` carries intent, bid,
//! fulfilment and expiry writes through the consensus settlement door.
//!
//! Relayer Policy Layer primitives.
//!
//! Relayers remain permissionless; safety comes from signed intent bounds,
//! deadlines, replay ids, fee caps, explicit owner escrow, anchored receipt
//! proofs and slashable RELAYER bonds. The settlement door pays the winning
//! solver from the locked maximum fee and refunds the remainder. An overdue
//! intent cannot be pruned silently: its owner is refunded and every
//! unhonoured bid is slashed before the rows leave consensus state.
//!
//! The inbound bridge direction remains separate: `split_bridge_fee` pays the
//! relayer out of an arriving asset. This module is the outbound intent layer,
//! and it deliberately accepts only externally anchored receipt proofs for the
//! settlement operation; unsupported action adapters fail closed rather than
//! claiming that a request completed.

use crate::core::address::Address;
use crate::core::transaction::{ExternalChain, RelayerExternalResult};
use bincode::Options;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_RELAYER_INTENTS: usize = 10_000;
pub const MAX_RELAYER_BIDS_PER_INTENT: usize = 64;
pub const MAX_RELAYER_SETTLEMENTS: usize = 10_000;
/// Consensus accepts a bounded Merkle receipt for an external intent. The
/// bridge result path uses the same ceiling, so an intent cannot smuggle a
/// larger proof through a different transaction door.
pub const MAX_RELAYER_INTENT_PROOF_BYTES: u64 = 4 * 1024;

/// A block-only intent-layer write. The signed transaction sender is the actor:
/// the intent owner opens, the relayer bids and fulfills, and anyone may expire
/// an overdue intent to return its escrow and slash unhonoured bids.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayerIntentTx {
    /// Open an intent and lock `intent.max_fee` from its owner.
    Open {
        intent: Box<UserIntent>,
        policy: Box<PolicyEnvelope>,
    },
    /// Commit a solver quote and slashable proof commitment.
    Bid(Box<SolverBid>),
    /// Fulfil the sender's bid with an anchored external receipt proof.
    Settle {
        intent_id: [u8; 32],
        paid_fee: u64,
        result: Box<RelayerExternalResult>,
    },
    /// Expire an intent after its deadline, refunding its owner and slashing
    /// every bid that was committed but not honoured.
    Expire { intent_id: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayerActionKind {
    ExternalTransaction {
        chain: ExternalChain,
        target_address: String,
        payload_hash: [u8; 32],
    },
    DwebResolve {
        name: String,
    },
    PollenRead {
        asset_id: crate::pollen::AssetId,
        grant_id: crate::pollen::GrantId,
    },
}

impl RelayerActionKind {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            RelayerActionKind::ExternalTransaction {
                target_address,
                payload_hash,
                ..
            } => {
                if target_address.is_empty() || target_address.len() > 256 {
                    return Err("RelayerAction external target_address length invalid".into());
                }
                if target_address.bytes().any(|b| b.is_ascii_whitespace()) {
                    return Err(
                        "RelayerAction external target_address cannot contain whitespace".into(),
                    );
                }
                if *payload_hash == [0u8; 32] {
                    return Err("RelayerAction external payload_hash cannot be zero".into());
                }
            }
            RelayerActionKind::DwebResolve { name } => {
                if name.is_empty() || name.len() > 253 {
                    return Err("RelayerAction dweb name length invalid".into());
                }
                if name.contains("..") || name.contains('/') || name.bytes().any(|b| b == 0) {
                    return Err("RelayerAction dweb name contains an invalid label".into());
                }
            }
            RelayerActionKind::PollenRead { asset_id, grant_id } => {
                if *asset_id == crate::pollen::AssetId::zero()
                    || *grant_id == crate::pollen::GrantId::zero()
                {
                    return Err("RelayerAction pollen ids cannot be zero".into());
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEnvelope {
    pub owner: Address,
    pub session_key: Option<Address>,
    pub spending_cap: u64,
    pub allowed_domains: Vec<u32>,
    pub requires_multisig: bool,
    pub requires_hsm: bool,
    pub expires_at_block: u64,
}

impl PolicyEnvelope {
    pub fn validate_for_owner(&self, owner: &Address, current_block: u64) -> Result<(), String> {
        if self.owner == Address::zero() {
            return Err("PolicyEnvelope owner cannot be zero".into());
        }
        if &self.owner != owner {
            return Err("PolicyEnvelope owner mismatch".into());
        }
        if let Some(session_key) = self.session_key {
            if session_key == Address::zero() {
                return Err("PolicyEnvelope session_key cannot be zero".into());
            }
        }
        if self.expires_at_block <= current_block {
            return Err("PolicyEnvelope expired".into());
        }
        if self.spending_cap == 0 {
            return Err("PolicyEnvelope spending_cap must be >= 1".into());
        }
        if self.allowed_domains.len() > 64 {
            return Err("PolicyEnvelope allowed_domains too large".into());
        }
        if self.allowed_domains.contains(&0) {
            return Err("PolicyEnvelope allowed_domains cannot contain zero".into());
        }
        Ok(())
    }

    pub fn policy_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_RELAYER_POLICY_ENVELOPE_V1");
        hasher.update(self.owner.as_bytes());
        match self.session_key {
            Some(session) => {
                hasher.update([1u8]);
                hasher.update(session.as_bytes());
            }
            None => hasher.update([0u8]),
        }
        hasher.update(self.spending_cap.to_le_bytes());
        hasher.update((self.allowed_domains.len() as u64).to_le_bytes());
        for domain in &self.allowed_domains {
            hasher.update(domain.to_le_bytes());
        }
        hasher.update([u8::from(self.requires_multisig)]);
        hasher.update([u8::from(self.requires_hsm)]);
        hasher.update(self.expires_at_block.to_le_bytes());
        hasher.finalize().into()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserIntent {
    pub intent_id: [u8; 32],
    pub owner: Address,
    pub source_domain: u32,
    pub target_domain: u32,
    pub action: RelayerActionKind,
    pub max_fee: u64,
    pub deadline_block: u64,
    pub replay_nonce: u64,
    pub policy_hash: [u8; 32],
    /// The only address on the target chain whose `intent-executed` event may
    /// settle this intent.
    ///
    /// The settlement receipt proves a root the chain anchored; it does not
    /// prove who emitted the event under it. Without this field every account
    /// on the target chain could emit an event naming the intent id, repeating
    /// the action's payload hash and carrying the right kind, and collect the
    /// escrow without doing the work. The owner names the emitter it expects
    /// when it locks the fee, and the id commits to it.
    #[serde(default)]
    pub expected_emitter: Address,
}

impl UserIntent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: Address,
        source_domain: u32,
        target_domain: u32,
        action: RelayerActionKind,
        max_fee: u64,
        deadline_block: u64,
        replay_nonce: u64,
        policy_hash: [u8; 32],
        expected_emitter: Address,
    ) -> Self {
        let mut intent = Self {
            intent_id: [0u8; 32],
            owner,
            source_domain,
            target_domain,
            action,
            max_fee,
            deadline_block,
            replay_nonce,
            policy_hash,
            expected_emitter,
        };
        intent.intent_id = intent.calculate_id();
        intent
    }

    pub fn calculate_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // V2: the emitter is part of the id. A `V1` id did not commit to one,
        // so it could name a different emitter than the owner chose.
        hasher.update(b"BDLM_RELAYER_USER_INTENT_V2");
        hasher.update(self.owner.as_bytes());
        hasher.update(self.source_domain.to_le_bytes());
        hasher.update(self.target_domain.to_le_bytes());
        encode_action(&self.action, &mut hasher);
        hasher.update(self.max_fee.to_le_bytes());
        hasher.update(self.deadline_block.to_le_bytes());
        hasher.update(self.replay_nonce.to_le_bytes());
        hasher.update(self.policy_hash);
        hasher.update(self.expected_emitter.as_bytes());
        hasher.finalize().into()
    }

    pub fn verify_id(&self) -> bool {
        self.intent_id == self.calculate_id()
    }

    pub fn validate(&self, policy: &PolicyEnvelope, current_block: u64) -> Result<(), String> {
        if !self.verify_id() {
            return Err("UserIntent id mismatch".into());
        }
        if self.expected_emitter == Address::zero() {
            return Err("UserIntent expected_emitter cannot be zero".into());
        }
        if self.owner == Address::zero() {
            return Err("UserIntent owner cannot be zero".into());
        }
        if self.source_domain == 0 || self.target_domain == 0 {
            return Err("UserIntent domains cannot be zero".into());
        }
        self.action.validate()?;
        policy.validate_for_owner(&self.owner, current_block)?;
        if self.policy_hash == [0u8; 32] || self.policy_hash != policy.policy_hash() {
            return Err("UserIntent policy_hash mismatch".into());
        }
        if self.deadline_block <= current_block {
            return Err("UserIntent expired".into());
        }
        if self.max_fee == 0 {
            return Err("UserIntent max_fee must be >= 1".into());
        }
        if self.max_fee > policy.spending_cap {
            return Err("UserIntent max_fee exceeds policy spending_cap".into());
        }
        if !policy.allowed_domains.is_empty()
            && (!policy.allowed_domains.contains(&self.source_domain)
                || !policy.allowed_domains.contains(&self.target_domain))
        {
            return Err("UserIntent domain not allowed by policy".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolverBid {
    pub intent_id: [u8; 32],
    pub relayer: Address,
    pub quoted_fee: u64,
    pub proof_commitment: [u8; 32],
    pub bond: u64,
    pub expires_at_block: u64,
}

impl SolverBid {
    pub fn validate_for_intent(
        &self,
        intent: &UserIntent,
        current_block: u64,
    ) -> Result<(), String> {
        if self.intent_id != intent.intent_id {
            return Err("SolverBid intent_id mismatch".into());
        }
        if self.relayer == Address::zero() {
            return Err("SolverBid relayer cannot be zero".into());
        }
        if self.quoted_fee == 0 || self.quoted_fee > intent.max_fee {
            return Err("SolverBid quoted_fee must be >0 and <= intent.max_fee".into());
        }
        if self.proof_commitment == [0u8; 32] {
            return Err("SolverBid proof_commitment cannot be zero".into());
        }
        if self.bond == 0 {
            return Err("SolverBid bond must be >= 1".into());
        }
        if self.expires_at_block <= current_block {
            return Err("SolverBid expired".into());
        }
        // A bid may lapse before the intent's deadline. `expire_intent` only
        // hands back - and the settlement only slashes - the bids still live
        // at the deadline (`expires_at_block >= intent.deadline_block`), so a
        // solver that signed a shorter window is dropped from the auction
        // rather than punished for a block it never promised. Refusing the bid
        // here would instead make a long-deadline intent unservable whenever
        // the deadline outlives the bid lifetime a solver is willing to sign.
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentSettlementStatus {
    Pending,
    Executed,
    Expired,
    Slashed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSettlement {
    pub intent_id: [u8; 32],
    pub relayer: Address,
    pub paid_fee: u64,
    pub settled_at_block: u64,
    pub status: IntentSettlementStatus,
}

/// Verify that `result` is anchored, and hand back the message it proves.
///
/// The checks every message-carrying external result needs before anyone
/// reads its message: success, a bounded transaction hash and proof, a
/// non-zero root that is the one anchored in consensus state for the
/// result's chain, a well-formed message id with no sender envelope, and a
/// Merkle path from the result leaf (which commits to the message fields)
/// to that root. What the message must say is the caller's question.
pub fn verify_anchored_result<'a>(
    external_roots: &BTreeMap<u32, [u8; 32]>,
    result: &'a RelayerExternalResult,
) -> Result<&'a crate::cross_domain::message::CrossDomainMessage, String> {
    if !result.success {
        return Err("external result reports failure".into());
    }
    if result.tx_hash.is_empty() || result.tx_hash.len() > 256 {
        return Err("external result tx_hash length invalid".into());
    }
    if result.external_state_root == [0u8; 32] {
        return Err("external result root cannot be zero".into());
    }
    if result.receipt_proof.len() as u64 > MAX_RELAYER_INTENT_PROOF_BYTES {
        return Err("external result receipt proof exceeds the consensus bound".into());
    }
    let message = result
        .message
        .as_ref()
        .ok_or_else(|| "external result carries no message".to_string())?;
    if !message.verify_id() {
        return Err("external result message id is invalid".into());
    }
    if !message.sender_public_key.is_empty() || !message.sender_signature.is_empty() {
        return Err("external result message carries a sender envelope".into());
    }
    if message.source_domain != result.chain.domain_id() {
        return Err("external result message comes from another domain than its chain".into());
    }
    match external_roots.get(&result.chain.domain_id()) {
        Some(root) if *root == result.external_state_root => {}
        _ => return Err("external result root is not anchored for its chain".into()),
    }
    let proof: crate::cross_domain::event_tree::MerkleProof = bincode::options()
        .with_fixint_encoding()
        .with_limit(MAX_RELAYER_INTENT_PROOF_BYTES)
        .deserialize(&result.receipt_proof)
        .map_err(|e| format!("invalid external result receipt proof: {e}"))?;
    if proof.siblings.len() > 64 || proof.leaf != result.result_leaf() {
        return Err("external result receipt proof leaf/path is invalid".into());
    }
    if !proof.verify(result.external_state_root) {
        return Err("external result receipt proof does not reach the anchored root".into());
    }
    Ok(message)
}

/// The message kind an external executor emits when it has carried out an
/// intent: the adapter turns that event into the cross-domain message a
/// settlement result carries.
pub const INTENT_EXECUTED_KIND: &[u8] = b"budlum/relayer/intent-executed/v1";

/// Verify an external receipt used to fulfil a relayer intent.
///
/// The result has to prove that *this* intent was carried out, not merely
/// that something happened on the target chain: on top of
/// [`verify_anchored_result`], its message must name the intent
/// (`correlation_id`), repeat the action's payload hash and carry the
/// intent-executed kind. A solver cannot settle with a self-signed receipt,
/// with a root nobody anchored, or with a real but unrelated event.
pub fn verify_intent_result(
    external_roots: &BTreeMap<u32, [u8; 32]>,
    intent: &UserIntent,
    result: &RelayerExternalResult,
) -> Result<(), String> {
    let RelayerActionKind::ExternalTransaction {
        chain,
        payload_hash,
        ..
    } = &intent.action
    else {
        return Err("only externally anchored relayer intents have a settlement verifier".into());
    };
    if result.chain != *chain {
        return Err("relayer intent result names another chain than the intent".into());
    }
    let message = verify_anchored_result(external_roots, result)?;
    if message.correlation_id != Some(intent.intent_id)
        || message.payload_hash != *payload_hash
        || message.kind
            != crate::cross_domain::message::MessageKind::Custom(INTENT_EXECUTED_KIND.to_vec())
    {
        return Err("relayer intent result does not prove this intent was executed".into());
    }
    // Who emitted it. The message's `sender` is the emitting account on the
    // source chain, and the owner fixed which one counts when it opened the
    // intent. Without this an id, a payload hash and a kind are enough for any
    // account on the target chain to claim the work.
    if message.sender != intent.expected_emitter {
        return Err(format!(
            "relayer intent result was emitted by {} and not by the intent's emitter {}",
            message.sender, intent.expected_emitter
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayerPolicyRegistry {
    #[serde(with = "crate::core::map_keys")]
    pub intents: BTreeMap<[u8; 32], UserIntent>,
    #[serde(with = "crate::core::map_keys")]
    pub bids: BTreeMap<[u8; 32], Vec<SolverBid>>,
    /// Maximum fee locked by the intent owner. This is explicit consensus
    /// state: it is debited from the owner and cannot disappear in a prune.
    #[serde(default, with = "crate::core::map_keys")]
    pub escrowed: BTreeMap<[u8; 32], u64>,
    #[serde(with = "crate::core::map_keys")]
    pub settlements: BTreeMap<[u8; 32], IntentSettlement>,
    /// Every intent id that was ever settled. Settlement rows are pruned by
    /// age to bound the map; this set is what keeps a pruned intent from
    /// being settled a second time, so it is never pruned while the intent
    /// itself is still known.
    #[serde(default)]
    pub settled_intents: BTreeSet<[u8; 32]>,
}

impl RelayerPolicyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
            && self.bids.is_empty()
            && self.escrowed.is_empty()
            && self.settlements.is_empty()
            && self.settled_intents.is_empty()
    }

    pub fn submit_intent(
        &mut self,
        intent: UserIntent,
        policy: &PolicyEnvelope,
        current_block: u64,
    ) -> Result<[u8; 32], String> {
        intent.validate(policy, current_block)?;
        self.prune_expired(current_block);
        if self.intents.contains_key(&intent.intent_id) {
            return Err("RelayerPolicyRegistry intent already exists".into());
        }
        if self.intents.len() >= MAX_RELAYER_INTENTS {
            return Err("RelayerPolicyRegistry intent limit exceeded".into());
        }
        let id = intent.intent_id;
        self.intents.insert(id, intent);
        Ok(id)
    }

    pub fn lock_escrow(&mut self, intent_id: [u8; 32], amount: u64) -> Result<(), String> {
        if amount == 0 {
            return Err("RelayerPolicyRegistry cannot lock zero escrow".into());
        }
        if !self.intents.contains_key(&intent_id) {
            return Err("RelayerPolicyRegistry intent not found".into());
        }
        if self.escrowed.contains_key(&intent_id) {
            return Err("RelayerPolicyRegistry intent escrow already exists".into());
        }
        self.escrowed.insert(intent_id, amount);
        Ok(())
    }

    /// Intent fees locked from their owners and not yet paid or refunded.
    #[must_use]
    pub fn total_escrowed_supply(&self) -> u128 {
        self.escrowed.values().fold(0u128, |total, amount| {
            total.saturating_add(u128::from(*amount))
        })
    }

    pub fn escrowed_amount(&self, intent_id: &[u8; 32]) -> u64 {
        self.escrowed.get(intent_id).copied().unwrap_or(0)
    }

    pub fn take_escrow(&mut self, intent_id: &[u8; 32]) -> Option<u64> {
        self.escrowed.remove(intent_id)
    }

    /// Remove an overdue intent and mark it settled as expired. The returned
    /// bids are the exact commitments that the transaction door must slash;
    /// pruning cannot silently erase an unhonoured bid or its owner's refund.
    pub fn expire_intent(
        &mut self,
        intent_id: [u8; 32],
        current_block: u64,
    ) -> Result<(Address, u64, Vec<SolverBid>), String> {
        let intent = self
            .intents
            .get(&intent_id)
            .ok_or_else(|| "RelayerPolicyRegistry intent not found".to_string())?;
        if self.is_settled(&intent_id) {
            return Err("RelayerPolicyRegistry intent already settled".into());
        }
        if intent.deadline_block > current_block {
            return Err("RelayerPolicyRegistry intent is not expired".into());
        }
        let owner = intent.owner;
        let escrow = self
            .escrowed
            .remove(&intent_id)
            .ok_or_else(|| "RelayerPolicyRegistry intent has no escrow".to_string())?;
        // A bid whose own window closed before the intent's deadline was never a
        // commitment the deadline could test: it leaves with the intent but it
        // is not slashable. `submit_bid` now refuses such a bid, so this filter
        // matters for rows written before that rule existed.
        let bids: Vec<SolverBid> = self
            .bids
            .remove(&intent_id)
            .unwrap_or_default()
            .into_iter()
            .filter(|bid| bid.expires_at_block >= intent.deadline_block)
            .collect();
        self.intents.remove(&intent_id);
        self.settled_intents.insert(intent_id);
        let settlement = IntentSettlement {
            intent_id,
            relayer: Address::zero(),
            paid_fee: 0,
            settled_at_block: current_block,
            status: IntentSettlementStatus::Expired,
        };
        if self.settlements.len() >= MAX_RELAYER_SETTLEMENTS {
            self.prune_settlements(MAX_RELAYER_SETTLEMENTS.saturating_sub(1));
        }
        self.settlements.insert(intent_id, settlement);
        Ok((owner, escrow, bids))
    }

    pub fn submit_bid(&mut self, bid: SolverBid, current_block: u64) -> Result<(), String> {
        let intent = self
            .intents
            .get(&bid.intent_id)
            .ok_or_else(|| "RelayerPolicyRegistry intent not found".to_string())?;
        if self.is_settled(&bid.intent_id) {
            return Err("RelayerPolicyRegistry intent already settled".into());
        }
        if intent.deadline_block <= current_block {
            return Err("RelayerPolicyRegistry intent expired".into());
        }
        bid.validate_for_intent(intent, current_block)?;
        let bids = self.bids.entry(bid.intent_id).or_default();
        if bids.len() >= MAX_RELAYER_BIDS_PER_INTENT {
            return Err("RelayerPolicyRegistry bid limit exceeded".into());
        }
        if bids.iter().any(|existing| existing.relayer == bid.relayer) {
            return Err("RelayerPolicyRegistry duplicate relayer bid".into());
        }
        bids.push(bid);
        Ok(())
    }

    pub fn best_bid(&self, intent_id: &[u8; 32]) -> Option<&SolverBid> {
        self.bids.get(intent_id).and_then(|bids| {
            bids.iter().min_by(|a, b| {
                a.quoted_fee
                    .cmp(&b.quoted_fee)
                    .then_with(|| b.bond.cmp(&a.bond))
                    .then_with(|| a.relayer.as_bytes().cmp(b.relayer.as_bytes()))
            })
        })
    }

    pub fn settle_intent(
        &mut self,
        intent_id: [u8; 32],
        relayer: Address,
        paid_fee: u64,
        current_block: u64,
    ) -> Result<IntentSettlement, String> {
        let intent = self
            .intents
            .get(&intent_id)
            .ok_or_else(|| "RelayerPolicyRegistry intent not found".to_string())?;
        if self.is_settled(&intent_id) {
            return Err("RelayerPolicyRegistry intent already settled".into());
        }
        if intent.deadline_block <= current_block {
            return Err("RelayerPolicyRegistry intent expired".into());
        }
        // The auction pays the winning solver, not whichever bidder presents
        // the receipt first. An anchored receipt proof is public, so any
        // bonded relayer could otherwise reuse the winner's proof, settle
        // against its own (higher) quote and leave the solver that did the
        // external work unpaid for the gas it burned. `best_bid` is the one
        // price ordering the door documents: lowest quote, then highest bond,
        // then address for a deterministic tie-break.
        let bid = self
            .best_bid(&intent_id)
            .ok_or_else(|| "RelayerPolicyRegistry relayer bid not found".to_string())?;
        if bid.relayer != relayer {
            return Err(format!(
                "RelayerPolicyRegistry settlement names {relayer}, but the winning bid is \
                 {} at {} (lowest quote first)",
                bid.relayer, bid.quoted_fee
            ));
        }
        if bid.expires_at_block <= current_block {
            return Err("RelayerPolicyRegistry selected bid expired".into());
        }
        if paid_fee == 0 || paid_fee > bid.quoted_fee {
            return Err("RelayerPolicyRegistry paid_fee exceeds bid quote".into());
        }
        if self.settlements.len() >= MAX_RELAYER_SETTLEMENTS {
            self.prune_settlements(MAX_RELAYER_SETTLEMENTS.saturating_sub(1));
        }
        let settlement = IntentSettlement {
            intent_id,
            relayer,
            paid_fee,
            settled_at_block: current_block,
            status: IntentSettlementStatus::Executed,
        };
        self.settlements.insert(intent_id, settlement.clone());
        self.settled_intents.insert(intent_id);
        Ok(settlement)
    }

    /// Whether the intent was settled, including settlements whose row has
    /// since been pruned.
    fn is_settled(&self, intent_id: &[u8; 32]) -> bool {
        self.settled_intents.contains(intent_id) || self.settlements.contains_key(intent_id)
    }

    /// Drop only legacy/unescrowed intents past their deadline. Escrowed
    /// intents must go through the block-only `Expire` door so the owner is
    /// refunded and every unhonoured bid is slashed before the rows vanish.
    pub fn prune_expired(&mut self, current_block: u64) -> usize {
        let expired: Vec<[u8; 32]> = self
            .intents
            .iter()
            .filter_map(|(id, intent)| {
                (intent.deadline_block <= current_block && !self.escrowed.contains_key(id))
                    .then_some(*id)
            })
            .collect();
        for id in &expired {
            self.intents.remove(id);
            self.bids.remove(id);
            self.settled_intents.remove(id);
        }
        expired.len()
    }

    /// Bound the settlement rows, evicting the oldest `settled_at_block`
    /// first (ties broken by id, so every node evicts the same rows). The
    /// intent id stays in `settled_intents`, so a pruned settlement cannot be
    /// paid twice.
    pub fn prune_settlements(&mut self, max_settlements: usize) -> usize {
        if self.settlements.len() <= max_settlements {
            return 0;
        }
        let to_remove = self.settlements.len() - max_settlements;
        let mut by_age: Vec<(u64, [u8; 32])> = self
            .settlements
            .iter()
            .map(|(id, settlement)| (settlement.settled_at_block, *id))
            .collect();
        by_age.sort_unstable();
        for (_, key) in by_age.iter().take(to_remove) {
            self.settlements.remove(key);
        }
        to_remove
    }

    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_RELAYER_POLICY_REGISTRY_V1");
        for (id, intent) in &self.intents {
            hasher.update(b"intent");
            hasher.update(id);
            hasher.update(intent.calculate_id());
        }
        for (intent_id, amount) in &self.escrowed {
            hasher.update(b"escrow");
            hasher.update(intent_id);
            hasher.update(amount.to_le_bytes());
        }
        for (intent_id, bids) in &self.bids {
            hasher.update(b"bids");
            hasher.update(intent_id);
            for bid in bids {
                hasher.update(bid.intent_id);
                hasher.update(bid.relayer.as_bytes());
                hasher.update(bid.quoted_fee.to_le_bytes());
                hasher.update(bid.proof_commitment);
                hasher.update(bid.bond.to_le_bytes());
                hasher.update(bid.expires_at_block.to_le_bytes());
            }
        }
        for (id, settlement) in &self.settlements {
            hasher.update(b"settlement");
            hasher.update(id);
            hasher.update(settlement.relayer.as_bytes());
            hasher.update(settlement.paid_fee.to_le_bytes());
            hasher.update(settlement.settled_at_block.to_le_bytes());
            hasher.update([match settlement.status {
                IntentSettlementStatus::Pending => 1,
                IntentSettlementStatus::Executed => 2,
                IntentSettlementStatus::Expired => 3,
                IntentSettlementStatus::Slashed => 4,
            }]);
        }
        for id in &self.settled_intents {
            hasher.update(b"settled");
            hasher.update(id);
        }
        hasher.finalize().into()
    }
}

/// Fixed byte tag of an external chain. It does not depend on the variant
/// name, so renaming a variant never changes an intent id.
fn chain_tag(chain: &ExternalChain) -> Vec<u8> {
    match chain {
        ExternalChain::Ethereum => vec![0],
        ExternalChain::Solana => vec![1],
        ExternalChain::Bitcoin => vec![2],
        ExternalChain::Avalanche => vec![3],
        ExternalChain::Polygon => vec![4],
        ExternalChain::Arbitrum => vec![5],
        ExternalChain::Optimism => vec![6],
        ExternalChain::Custom(id) => {
            let mut tag = vec![7];
            tag.extend_from_slice(&id.to_le_bytes());
            tag
        }
    }
}

fn encode_action(action: &RelayerActionKind, hasher: &mut Sha256) {
    match action {
        RelayerActionKind::ExternalTransaction {
            chain,
            target_address,
            payload_hash,
        } => {
            hasher.update([0u8]);
            hasher.update(chain_tag(chain));
            hasher.update((target_address.len() as u64).to_le_bytes());
            hasher.update(target_address.as_bytes());
            hasher.update(payload_hash);
        }
        RelayerActionKind::DwebResolve { name } => {
            hasher.update([1u8]);
            hasher.update((name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
        }
        RelayerActionKind::PollenRead { asset_id, grant_id } => {
            hasher.update([2u8]);
            hasher.update(asset_id.0);
            hasher.update(grant_id.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_tags_are_fixed_bytes() {
        assert_eq!(chain_tag(&ExternalChain::Ethereum), vec![0]);
        assert_eq!(chain_tag(&ExternalChain::Custom(5)), vec![7, 5, 0, 0, 0]);
    }

    fn addr(byte: u8) -> Address {
        Address::from([byte; 32])
    }

    fn make_policy(owner: Address) -> PolicyEnvelope {
        PolicyEnvelope {
            owner,
            session_key: None,
            spending_cap: 100,
            allowed_domains: vec![1, 2],
            requires_multisig: false,
            requires_hsm: false,
            expires_at_block: 100,
        }
    }

    fn intent(owner: Address, policy: &PolicyEnvelope) -> UserIntent {
        UserIntent::new(
            owner,
            1,
            2,
            RelayerActionKind::DwebResolve {
                name: "ayaz.bud".into(),
            },
            50,
            50,
            7,
            policy.policy_hash(),
            addr(9),
        )
    }

    /// An anchored, well-formed result settles an intent only when its
    /// message names that intent and repeats its payload hash.
    #[test]
    fn an_intent_result_must_prove_this_intent() {
        use crate::cross_domain::message::{
            CrossDomainMessage, CrossDomainMessageParams, MessageKind,
        };
        let owner = addr(1);
        let policy = make_policy(owner);
        let chain = ExternalChain::Custom(2);
        let payload_hash = [0x5A; 32];
        let intent = UserIntent::new(
            owner,
            1,
            2,
            RelayerActionKind::ExternalTransaction {
                chain,
                target_address: "0xabc".into(),
                payload_hash,
            },
            50,
            50,
            7,
            policy.policy_hash(),
            addr(9),
        );
        let result_for = |correlation: [u8; 32], payload: [u8; 32]| {
            let message = CrossDomainMessage::new_correlated(
                CrossDomainMessageParams {
                    source_domain: chain.domain_id(),
                    target_domain: 1,
                    source_height: 9,
                    event_index: 0,
                    nonce: 0,
                    sender: addr(9),
                    recipient: owner,
                    payload_hash: payload,
                    kind: MessageKind::Custom(INTENT_EXECUTED_KIND.to_vec()),
                    expiry_height: 0,
                },
                correlation,
            );
            let mut result = RelayerExternalResult {
                chain,
                tx_hash: "0x01".into(),
                success: true,
                message: Some(message),
                receipt_proof: Vec::new(),
                external_state_root: [0u8; 32],
            };
            // A one-leaf tree: the anchored root is the leaf itself.
            let leaf = result.result_leaf();
            result.receipt_proof =
                bincode::serialize(&crate::cross_domain::event_tree::MerkleProof {
                    leaf,
                    index: 0,
                    siblings: Vec::new(),
                })
                .unwrap();
            result.external_state_root = leaf;
            result
        };

        let good = result_for(intent.intent_id, payload_hash);
        let roots = BTreeMap::from([(chain.domain_id(), good.external_state_root)]);
        assert!(verify_intent_result(&roots, &intent, &good).is_ok());

        // A real, anchored event about another intent settles nothing.
        let other = result_for([0x77; 32], payload_hash);
        let roots = BTreeMap::from([(chain.domain_id(), other.external_state_root)]);
        assert!(verify_intent_result(&roots, &intent, &other).is_err());

        // Nor does one with another payload.
        let wrong = result_for(intent.intent_id, [0x5B; 32]);
        let roots = BTreeMap::from([(chain.domain_id(), wrong.external_state_root)]);
        assert!(verify_intent_result(&roots, &intent, &wrong).is_err());

        // Nor an unanchored root.
        assert!(verify_intent_result(&BTreeMap::new(), &intent, &good).is_err());

        // Nor an event naming the intent, its payload and its kind but emitted
        // by somebody else: the owner fixed the emitter when it locked the fee.
        let impostor = {
            let message = CrossDomainMessage::new_correlated(
                CrossDomainMessageParams {
                    source_domain: chain.domain_id(),
                    target_domain: 1,
                    source_height: 9,
                    event_index: 0,
                    nonce: 0,
                    sender: addr(0xAB),
                    recipient: owner,
                    payload_hash,
                    kind: MessageKind::Custom(INTENT_EXECUTED_KIND.to_vec()),
                    expiry_height: 0,
                },
                intent.intent_id,
            );
            let mut result = RelayerExternalResult {
                chain,
                tx_hash: "0x02".into(),
                success: true,
                message: Some(message),
                receipt_proof: Vec::new(),
                external_state_root: [0u8; 32],
            };
            let leaf = result.result_leaf();
            result.receipt_proof =
                bincode::serialize(&crate::cross_domain::event_tree::MerkleProof {
                    leaf,
                    index: 0,
                    siblings: Vec::new(),
                })
                .unwrap();
            result.external_state_root = leaf;
            result
        };
        let roots = BTreeMap::from([(chain.domain_id(), impostor.external_state_root)]);
        assert!(verify_intent_result(&roots, &intent, &impostor).is_err());
    }

    #[test]
    fn intent_validates_without_relayer_whitelist() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        assert!(intent.validate(&policy, 10).is_ok());
    }

    #[test]
    fn intent_replay_nonce_changes_id() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let a = intent(owner, &policy);
        let mut b = intent(owner, &policy);
        b.replay_nonce = 8;
        b.intent_id = b.calculate_id();
        assert_ne!(a.intent_id, b.intent_id);
    }

    #[test]
    fn fee_cap_is_enforced() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let mut intent = intent(owner, &policy);
        intent.max_fee = 101;
        intent.intent_id = intent.calculate_id();
        assert!(intent
            .validate(&policy, 10)
            .unwrap_err()
            .contains("spending_cap"));
    }

    #[test]
    fn solver_bid_cannot_exceed_user_fee_cap() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        let bid = SolverBid {
            intent_id: intent.intent_id,
            relayer: addr(9),
            quoted_fee: 51,
            proof_commitment: [3u8; 32],
            bond: 10,
            expires_at_block: 80,
        };
        assert!(bid.validate_for_intent(&intent, 10).is_err());
    }

    #[test]
    fn policy_rejects_zero_owner_session_or_domain() {
        let mut policy = make_policy(addr(1));
        policy.owner = Address::zero();
        assert!(policy
            .validate_for_owner(&Address::zero(), 10)
            .unwrap_err()
            .contains("owner cannot be zero"));

        let mut policy = make_policy(addr(1));
        policy.session_key = Some(Address::zero());
        assert!(policy
            .validate_for_owner(&addr(1), 10)
            .unwrap_err()
            .contains("session_key"));

        let mut policy = make_policy(addr(1));
        policy.allowed_domains.push(0);
        assert!(policy
            .validate_for_owner(&addr(1), 10)
            .unwrap_err()
            .contains("allowed_domains"));
    }

    #[test]
    fn dweb_action_rejects_invalid_names() {
        for name in ["", "../ayaz.bud", "ayaz/bud", "bad..bud"] {
            assert!(RelayerActionKind::DwebResolve { name: name.into() }
                .validate()
                .is_err());
        }
    }

    #[test]
    fn pollen_read_action_requires_nonzero_ids() {
        let action = RelayerActionKind::PollenRead {
            asset_id: crate::pollen::AssetId::zero(),
            grant_id: crate::pollen::GrantId::from([1u8; 32]),
        };
        assert!(action.validate().unwrap_err().contains("cannot be zero"));
    }

    #[test]
    fn intent_rejects_zero_domain() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let mut intent = intent(owner, &policy);
        intent.target_domain = 0;
        intent.intent_id = intent.calculate_id();
        assert!(intent
            .validate(&policy, 10)
            .unwrap_err()
            .contains("domains cannot be zero"));
    }

    #[test]
    fn solver_bid_requires_proof_commitment() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        let bid = SolverBid {
            intent_id: intent.intent_id,
            relayer: addr(9),
            quoted_fee: 50,
            proof_commitment: [0u8; 32],
            bond: 10,
            expires_at_block: 80,
        };
        assert!(bid
            .validate_for_intent(&intent, 10)
            .unwrap_err()
            .contains("proof_commitment"));
    }

    #[test]
    fn registry_settles_best_bid_and_changes_root() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        let mut registry = RelayerPolicyRegistry::new();
        let intent_id = registry.submit_intent(intent.clone(), &policy, 10).unwrap();
        let first = SolverBid {
            intent_id,
            relayer: addr(9),
            quoted_fee: 40,
            proof_commitment: [3u8; 32],
            bond: 10,
            expires_at_block: 80,
        };
        let second = SolverBid {
            intent_id,
            relayer: addr(8),
            quoted_fee: 30,
            proof_commitment: [4u8; 32],
            bond: 20,
            expires_at_block: 80,
        };
        registry.submit_bid(first, 10).unwrap();
        registry.submit_bid(second.clone(), 10).unwrap();
        assert_eq!(
            registry.best_bid(&intent_id).unwrap().relayer,
            second.relayer
        );
        let before = registry.root();
        let settlement = registry
            .settle_intent(intent_id, second.relayer, second.quoted_fee, 20)
            .unwrap();
        assert_eq!(settlement.status, IntentSettlementStatus::Executed);
        assert_ne!(before, registry.root());
    }

    #[test]
    fn registry_rejects_unknown_intent_bid_and_duplicate_relayer_bid() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        let mut registry = RelayerPolicyRegistry::new();
        let bid = SolverBid {
            intent_id: intent.intent_id,
            relayer: addr(9),
            quoted_fee: 40,
            proof_commitment: [3u8; 32],
            bond: 10,
            expires_at_block: 80,
        };
        assert!(registry
            .submit_bid(bid.clone(), 10)
            .unwrap_err()
            .contains("not found"));
        registry.submit_intent(intent, &policy, 10).unwrap();
        registry.submit_bid(bid.clone(), 10).unwrap();
        assert!(registry
            .submit_bid(bid, 10)
            .unwrap_err()
            .contains("duplicate relayer"));
    }

    #[test]
    fn registry_rejects_expired_intent_settlement() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        let mut registry = RelayerPolicyRegistry::new();
        let intent_id = registry.submit_intent(intent, &policy, 10).unwrap();
        let bid = SolverBid {
            intent_id,
            relayer: addr(9),
            quoted_fee: 40,
            proof_commitment: [3u8; 32],
            bond: 10,
            expires_at_block: 80,
        };
        registry.submit_bid(bid, 10).unwrap();
        assert!(registry
            .settle_intent(intent_id, addr(9), 40, 50)
            .unwrap_err()
            .contains("expired"));
    }

    #[test]
    fn registry_prunes_expired_intents_and_bids() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        let mut registry = RelayerPolicyRegistry::new();
        let intent_id = registry.submit_intent(intent, &policy, 10).unwrap();
        registry
            .submit_bid(
                SolverBid {
                    intent_id,
                    relayer: addr(9),
                    quoted_fee: 40,
                    proof_commitment: [3u8; 32],
                    bond: 10,
                    expires_at_block: 80,
                },
                10,
            )
            .unwrap();
        assert_eq!(registry.prune_expired(50), 1);
        assert!(!registry.intents.contains_key(&intent_id));
        assert!(!registry.bids.contains_key(&intent_id));
    }

    #[test]
    fn registry_rejects_over_quote_and_expired_bid_settlement() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        let mut registry = RelayerPolicyRegistry::new();
        let intent_id = registry.submit_intent(intent, &policy, 10).unwrap();
        let bid = SolverBid {
            intent_id,
            relayer: addr(9),
            quoted_fee: 40,
            proof_commitment: [3u8; 32],
            bond: 10,
            expires_at_block: 30,
        };
        registry.submit_bid(bid, 10).unwrap();
        assert!(registry
            .settle_intent(intent_id, addr(9), 41, 20)
            .unwrap_err()
            .contains("paid_fee"));
        assert!(registry
            .settle_intent(intent_id, addr(9), 40, 30)
            .unwrap_err()
            .contains("bid expired"));
    }

    /// Pruning settlement rows must not reopen a settled intent. Rows go
    /// oldest first by `settled_at_block`, the replay guard stays until the
    /// intent itself expires.
    #[test]
    fn pruned_settlement_still_blocks_a_second_settlement() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let mut registry = RelayerPolicyRegistry::new();
        let bid_for = |intent_id, relayer, quoted_fee| SolverBid {
            intent_id,
            relayer,
            quoted_fee,
            proof_commitment: [3u8; 32],
            bond: 10,
            expires_at_block: 80,
        };
        let mut ids = Vec::new();
        for nonce in 0..3u64 {
            let mut intent = intent(owner, &policy);
            intent.replay_nonce = nonce;
            intent.intent_id = intent.calculate_id();
            let id = registry.submit_intent(intent, &policy, 10).unwrap();
            registry.submit_bid(bid_for(id, addr(9), 40), 10).unwrap();
            ids.push(id);
        }
        // Settled out of key order: the age order is ids[1], ids[2], ids[0].
        registry.settle_intent(ids[0], addr(9), 40, 30).unwrap();
        registry.settle_intent(ids[1], addr(9), 40, 20).unwrap();
        registry.settle_intent(ids[2], addr(9), 40, 25).unwrap();

        // Keeping one row evicts the two oldest, whatever their ids sort to.
        assert_eq!(registry.prune_settlements(1), 2);
        assert_eq!(
            registry.settlements.keys().copied().collect::<Vec<_>>(),
            vec![ids[0]]
        );

        // Every intent stays settled: no second payment and no fresh bid.
        for id in &ids {
            assert!(registry.is_settled(id));
            assert!(registry
                .settle_intent(*id, addr(9), 40, 35)
                .unwrap_err()
                .contains("already settled"));
        }
        assert!(registry
            .submit_bid(bid_for(ids[1], addr(8), 30), 35)
            .unwrap_err()
            .contains("already settled"));

        // The guard lives exactly as long as the intent it protects.
        assert_eq!(registry.prune_expired(50), 3);
        assert!(registry.settled_intents.is_empty());
        assert!(registry
            .settle_intent(ids[1], addr(9), 40, 50)
            .unwrap_err()
            .contains("not found"));
    }

    #[test]
    fn escrowed_expiry_returns_owner_value_and_marks_intent_settled() {
        let owner = addr(1);
        let policy = make_policy(owner);
        let intent = intent(owner, &policy);
        let mut registry = RelayerPolicyRegistry::new();
        let intent_id = registry.submit_intent(intent, &policy, 10).unwrap();
        registry.lock_escrow(intent_id, 50).unwrap();
        registry
            .submit_bid(
                SolverBid {
                    intent_id,
                    relayer: addr(9),
                    quoted_fee: 40,
                    proof_commitment: [3u8; 32],
                    bond: 10,
                    expires_at_block: 80,
                },
                10,
            )
            .unwrap();
        assert_eq!(registry.prune_expired(50), 0);
        let (returned_owner, escrow, bids) = registry.expire_intent(intent_id, 50).unwrap();
        assert_eq!(returned_owner, owner);
        assert_eq!(escrow, 50);
        assert_eq!(bids.len(), 1);
        assert!(registry.is_settled(&intent_id));
        assert!(registry.escrowed.is_empty());
    }
}
