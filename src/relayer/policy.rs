//! Relayer Policy Layer primitives (Phase 12 / ARENA4).
//!
//! This module models user intents and solver bids without introducing a
//! whitelist. Relayers remain permissionless; safety comes from signed intent
//! bounds, deadlines, replay ids, fee caps and slashable bid commitments.

use crate::core::address::Address;
use crate::core::transaction::ExternalChain;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
        if self.allowed_domains.iter().any(|domain| *domain == 0) {
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
}
