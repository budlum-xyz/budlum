//! Relayer Policy Layer primitives.
//!
//! This module models user intents and solver bids without introducing a
//! Whitelist. Relayers remain permissionless; safety comes from signed intent
//! Bounds, deadlines, replay ids, fee caps and slashable bid commitments.
//!
//! # Nothing on the chain reaches this module
//!
//! `UserIntent`, `SolverBid` and `IntentSettlement` have **zero** callers
//! Outside this file and the `pub use` in `relayer/mod.rs`. There is no
//! Transaction type that carries an intent, no `ChainCommand` that accepts a
//! Bid, no RPC method that settles one. The 768 lines below are a complete
//! Economic design with no edge into consensus.
//!
//! What actually happens today, in `executor.rs`:
//!
//! ```text
//! TransactionType::UniversalRelay(ext_tx) => {
//!     let sender = state.get_or_create(&tx.from);
//!     sender.balance = sender.balance.checked_sub(tx.fee)?;
//!     sender.nonce = sender.nonce.saturating_add(1);
//! }
//! ```
//!
//! The sender pays `tx.fee`, and that fee is credited to the **block
//! Producer**, not to the relayer that will spend external gas executing the
//! Request. So relaying is unpaid work: a relayer bonds (`RoleId` 3), burns gas
//! On Ethereum, and earns nothing from the chain for it. `max_fee` is not
//! Consulted - the flat-fee protocol requires `max_fee == fee` - so a user
//! Cannot express a ceiling either, and nothing binds the relayer to a price
//! Before it acts.
//!
//! The inbound direction *is* wired: `split_bridge_fee` pays the relayer out
//! Of the arriving asset when a bridge transfer lands on Budlum. The outbound
//! Direction, where this module would apply, is not.
//!
//! This is a design that has not been connected, not a design that failed.
//! Wiring it means a transaction type, a settlement path that moves `paid_fee`
//! From the user to the winning solver, and a slash path for a bid that is
//! Committed and not honoured - each of which is a consensus change. Recorded
//! Here so the gap is visible at the definition rather than inferred from a
//! Grep returning nothing.

use crate::core::address::Address;
use crate::core::transaction::ExternalChain;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_RELAYER_INTENTS: usize = 10_000;
pub const MAX_RELAYER_BIDS_PER_INTENT: usize = 64;
pub const MAX_RELAYER_SETTLEMENTS: usize = 10_000;

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
        };
        intent.intent_id = intent.calculate_id();
        intent
    }

    pub fn calculate_id(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_RELAYER_USER_INTENT_V1");
        hasher.update(self.owner.as_bytes());
        hasher.update(self.source_domain.to_le_bytes());
        hasher.update(self.target_domain.to_le_bytes());
        encode_action(&self.action, &mut hasher);
        hasher.update(self.max_fee.to_le_bytes());
        hasher.update(self.deadline_block.to_le_bytes());
        hasher.update(self.replay_nonce.to_le_bytes());
        hasher.update(self.policy_hash);
        hasher.finalize().into()
    }

    pub fn verify_id(&self) -> bool {
        self.intent_id == self.calculate_id()
    }

    pub fn validate(&self, policy: &PolicyEnvelope, current_block: u64) -> Result<(), String> {
        if !self.verify_id() {
            return Err("UserIntent id mismatch".into());
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RelayerPolicyRegistry {
    pub intents: BTreeMap<[u8; 32], UserIntent>,
    pub bids: BTreeMap<[u8; 32], Vec<SolverBid>>,
    pub settlements: BTreeMap<[u8; 32], IntentSettlement>,
}

impl RelayerPolicyRegistry {
    pub fn new() -> Self {
        Self::default()
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

    pub fn submit_bid(&mut self, bid: SolverBid, current_block: u64) -> Result<(), String> {
        let intent = self
            .intents
            .get(&bid.intent_id)
            .ok_or_else(|| "RelayerPolicyRegistry intent not found".to_string())?;
        if self.settlements.contains_key(&bid.intent_id) {
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
        if self.settlements.contains_key(&intent_id) {
            return Err("RelayerPolicyRegistry intent already settled".into());
        }
        if intent.deadline_block <= current_block {
            return Err("RelayerPolicyRegistry intent expired".into());
        }
        let bid = self
            .bids
            .get(&intent_id)
            .and_then(|bids| bids.iter().find(|bid| bid.relayer == relayer))
            .ok_or_else(|| "RelayerPolicyRegistry relayer bid not found".to_string())?;
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
        Ok(settlement)
    }

    pub fn prune_expired(&mut self, current_block: u64) -> usize {
        let expired: Vec<[u8; 32]> = self
            .intents
            .iter()
            .filter_map(|(id, intent)| (intent.deadline_block <= current_block).then_some(*id))
            .collect();
        for id in &expired {
            self.intents.remove(id);
            self.bids.remove(id);
        }
        expired.len()
    }

    pub fn prune_settlements(&mut self, max_settlements: usize) -> usize {
        if self.settlements.len() <= max_settlements {
            return 0;
        }
        let to_remove = self.settlements.len() - max_settlements;
        let keys: Vec<[u8; 32]> = self.settlements.keys().take(to_remove).copied().collect();
        for key in &keys {
            self.settlements.remove(key);
        }
        keys.len()
    }

    pub fn root(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_RELAYER_POLICY_REGISTRY_V1");
        for (id, intent) in &self.intents {
            hasher.update(b"intent");
            hasher.update(id);
            hasher.update(intent.calculate_id());
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
        hasher.finalize().into()
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
            hasher.update(format!("{:?}", chain).as_bytes());
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
        )
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

    /// The policy layer is unreachable from consensus, and the relay fee goes
    /// To the block producer rather than the relayer.
    ///
    /// `UserIntent`, `SolverBid` and `IntentSettlement` have no callers outside
    /// This module. No transaction type carries an intent, no `ChainCommand`
    /// Accepts a bid, no RPC settles one. Meanwhile `TransactionType::UniversalRelay`
    /// Debits `tx.fee` from the sender and stops - and that fee is credited to
    /// The block producer, so a relayer that spends external gas on the request
    /// Earns nothing from the chain for it.
    ///
    /// This pins the gap so it cannot be half-closed by accident. When a real
    /// Settlement path lands, this test fails and whoever wired it has to
    /// Delete it deliberately - having also moved `paid_fee` to the winning
    /// Solver and given a committed-but-unhonoured bid something to lose.
    #[test]
    fn the_policy_layer_is_still_unwired_and_relaying_is_still_unpaid() {
        let executor_src = include_str!("../execution/executor.rs");

        for kind in ["UserIntent", "SolverBid", "IntentSettlement"] {
            assert!(
                !executor_src.contains(kind),
                "{kind} now reaches the executor - settle it to the solver and \
                 give an unhonoured bid something to lose, then drop this test"
            );
        }

        // The relay arm still only takes the flat fee. If it grew a credit to
        // anyone, this window would no longer look like this.
        let at = executor_src
            .find("TransactionType::UniversalRelay(ext_tx)")
            .expect("the relay arm must still exist");
        let arm = &executor_src[at..at + 600];
        let end = arm
            .find("TransactionType::RelayerResult")
            .unwrap_or(arm.len());
        let arm = &arm[..end];
        assert!(
            arm.contains("checked_sub(tx.fee)"),
            "the relay arm no longer debits a flat fee - re-read this test"
        );
        assert!(
            !arm.contains("try_add_balance") && !arm.contains("checked_add"),
            "the relay arm now credits someone - if that is the relayer, this \
             gap is closed and the test should go"
        );
    }
}
