use crate::core::address::Address;
use crate::core::constitution::{ConstitutionParameter, ConstitutionRegistry};
use crate::registry::params::RegistryParams;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Phase 11.16: accepted parameter proposals activate after this delay.
pub const GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS: u64 = 10;

/// Phase 11.16: minimal on-chain governance is parameter-only and whitelist-bound.
pub const GOVERNANCE_PARAMETER_WHITELIST: &[&str] = &[
    "min_stake",
    "unbonding_epochs",
    "double_sign_slash_ratio_fixed",
    "liveness_slash_ratio_fixed",
    "malicious_slash_ratio_fixed",
];

pub fn is_governance_parameter_whitelisted(key: &str) -> bool {
    GOVERNANCE_PARAMETER_WHITELIST.contains(&key)
}

pub fn validate_governance_parameter_update(key: &str, value: &str) -> Result<(), String> {
    if !is_governance_parameter_whitelisted(key) {
        return Err(format!("governance parameter is not whitelisted: {key}"));
    }

    let mut params = RegistryParams::default();
    match key {
        "min_stake" => {
            params.min_stake = value
                .parse::<u64>()
                .map_err(|e| format!("invalid min_stake: {e}"))?;
        }
        "unbonding_epochs" => {
            params.unbonding_epochs = value
                .parse::<u64>()
                .map_err(|e| format!("invalid unbonding_epochs: {e}"))?;
        }
        "double_sign_slash_ratio_fixed" => {
            params.double_sign_slash_ratio_fixed = value
                .parse::<u64>()
                .map_err(|e| format!("invalid double_sign_slash_ratio_fixed: {e}"))?;
        }
        "liveness_slash_ratio_fixed" => {
            params.liveness_slash_ratio_fixed = value
                .parse::<u64>()
                .map_err(|e| format!("invalid liveness_slash_ratio_fixed: {e}"))?;
        }
        "malicious_slash_ratio_fixed" => {
            params.malicious_slash_ratio_fixed = value
                .parse::<u64>()
                .map_err(|e| format!("invalid malicious_slash_ratio_fixed: {e}"))?;
        }
        _ => unreachable!("whitelist checked above"),
    }
    params.validate()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalType {
    ChangeBaseFee(u64),
    ChangeBlockReward(u64),
    SlashValidator {
        address: Address,
        /// V40 (ARENAX): Hash of the slashing evidence that proves misbehavior.
        /// Governance slash now requires cryptographic proof, not just a vote.
        evidence_hash: [u8; 32],
    },
    ParameterUpdate(String, String),
    /// P5 ADIM11 Bulgu 33+Governance: Whitelist a verifier via governance vote.
    /// Enables decentralized, vote-based verifier onboarding.
    WhitelistVerifier {
        address: Address,
    },
    /// P5 ADIM11 Bulgu 33+Governance: Remove a verifier from the whitelist.
    DewhitelistVerifier {
        address: Address,
    },
    /// Phase 12: DAO-managed encryption parameters for Pollen/B.U.D.
    /// This is parameter-only governance: no decrypt/key/read override exists.
    SetEncryptionPolicy(crate::pollen::EncryptionPolicy),
    /// Phase 12: Constitution Engine parameter update. Hard guardrails are
    /// validated fail-closed and cannot be weakened by governance.
    SetConstitutionParameter(ConstitutionParameter),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalStatus {
    Active,
    Passed,
    Failed,
    Executed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub proposer: Address,
    pub p_type: ProposalType,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub votes_for: u64,     // Total stake voting FOR
    pub votes_against: u64, // Total stake voting AGAINST
    pub status: ProposalStatus,
    pub voters: HashMap<Address, bool>, // Address -> Vote (true = for)
    /// Phase 11.16: vote-weight snapshot captured when each validator votes.
    #[serde(default)]
    pub voter_weights: HashMap<Address, u64>,
    /// Phase 11.16: optional delayed activation epoch after a proposal passes.
    #[serde(default)]
    pub activation_epoch: Option<u64>,
}

impl Proposal {
    pub fn new(
        id: u64,
        proposer: Address,
        p_type: ProposalType,
        start_epoch: u64,
        duration: u64,
    ) -> Self {
        Proposal {
            id,
            proposer,
            p_type,
            start_epoch,
            end_epoch: start_epoch + duration,
            votes_for: 0,
            votes_against: 0,
            status: ProposalStatus::Active,
            voters: HashMap::new(),
            voter_weights: HashMap::new(),
            activation_epoch: None,
        }
    }

    pub fn activation_epoch(&self) -> u64 {
        self.activation_epoch.unwrap_or(self.end_epoch)
    }

    pub fn activation_ready(&self, current_epoch: u64) -> bool {
        current_epoch >= self.activation_epoch()
    }

    pub fn add_vote(
        &mut self,
        voter: Address,
        stake: u64,
        vote_for: bool,
        current_epoch: u64,
    ) -> Result<(), String> {
        if self.status != ProposalStatus::Active {
            return Err("Proposal is not active".into());
        }
        // H2: voting window closed after end_epoch (pairs with V130 finalize gate).
        if current_epoch >= self.end_epoch {
            return Err("Voting period has ended".into());
        }
        if self.voters.contains_key(&voter) {
            return Err("Already voted".into());
        }

        if vote_for {
            self.votes_for = self.votes_for.saturating_add(stake);
        } else {
            self.votes_against = self.votes_against.saturating_add(stake);
        }
        self.voters.insert(voter, vote_for);
        self.voter_weights.insert(voter, stake);
        Ok(())
    }

    pub fn vote_weight_of(&self, voter: &Address) -> u64 {
        self.voter_weights.get(voter).copied().unwrap_or(0)
    }

    /// Phase 11.16: reduce only the stake weight originally snapshotted for a voter.
    /// The address remains in `voters`, so moving/re-staking stake cannot vote twice.
    pub fn reduce_vote_weight(&mut self, voter: &Address, reduction: u64) {
        let Some(vote_for) = self.voters.get(voter).copied() else {
            return;
        };
        let current = self.voter_weights.get(voter).copied().unwrap_or(0);
        let applied = current.min(reduction);
        if applied == 0 {
            return;
        }
        if vote_for {
            self.votes_for = self.votes_for.saturating_sub(applied);
        } else {
            self.votes_against = self.votes_against.saturating_sub(applied);
        }
        self.voter_weights
            .insert(*voter, current.saturating_sub(applied));
    }

    /// V130 fix (ARENAS): Finalize proposal — now requires current_epoch >= end_epoch.
    /// Previously, finalize() could be called at any time, allowing early-finalize
    /// attacks where a proposal with sufficient votes could be forced through
    /// before the voting period ended.
    pub fn finalize(&mut self, total_stake: u64, quorum_pct: u64, current_epoch: u64) {
        if self.status != ProposalStatus::Active {
            return;
        }
        // V130: Voting period must have elapsed before finalization
        if current_epoch < self.end_epoch {
            return;
        }
        // V70: Use u128 to prevent overflow in the quorum calculation
        let total_votes = (self.votes_for as u128) + (self.votes_against as u128);
        let quorum_threshold = (total_stake as u128) * (quorum_pct as u128);
        let reached_quorum = total_votes * 100 >= quorum_threshold;
        if reached_quorum && self.votes_for > self.votes_against {
            self.status = ProposalStatus::Passed;
        } else {
            self.status = ProposalStatus::Failed;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GovernanceState {
    pub proposals: Vec<Proposal>,
    pub next_proposal_id: u64,
    #[serde(default)]
    pub constitution: ConstitutionRegistry,
}

impl GovernanceState {
    pub fn create_proposal(
        &mut self,
        proposer: Address,
        p_type: ProposalType,
        current_epoch: u64,
        duration: u64,
    ) -> Result<u64, String> {
        match &p_type {
            ProposalType::ParameterUpdate(key, value) => {
                validate_governance_parameter_update(key, value)?;
            }
            ProposalType::SetEncryptionPolicy(policy) => policy.validate()?,
            ProposalType::SetConstitutionParameter(parameter) => parameter.validate_update()?,
            _ => {}
        }

        // V68: Validate proposal duration
        const MIN_PROPOSAL_DURATION: u64 = 10; // Minimum 10 epochs
        const MAX_PROPOSAL_DURATION: u64 = 100_000; // Maximum 100,000 epochs
        if duration < MIN_PROPOSAL_DURATION || duration > MAX_PROPOSAL_DURATION {
            return Err(format!(
                "Proposal duration must be between {} and {} epochs",
                MIN_PROPOSAL_DURATION, MAX_PROPOSAL_DURATION
            ));
        }

        // V69: Limit active proposals to prevent state bloat
        const MAX_ACTIVE_PROPOSALS: usize = 100;
        let active_count = self
            .proposals
            .iter()
            .filter(|p| p.status == ProposalStatus::Active)
            .count();
        if active_count >= MAX_ACTIVE_PROPOSALS {
            return Err("Too many active proposals".into());
        }

        let end_epoch = current_epoch
            .checked_add(duration)
            .ok_or_else(|| "Proposal end_epoch overflow".to_string())?;

        let id = self.next_proposal_id;
        let mut proposal = Proposal::new(id, proposer, p_type, current_epoch, duration);
        if matches!(proposal.p_type, ProposalType::ParameterUpdate(_, _)) {
            proposal.activation_epoch = Some(
                end_epoch
                    .checked_add(GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS)
                    .ok_or_else(|| "Proposal activation_epoch overflow".to_string())?,
            );
        }
        self.proposals.push(proposal);
        self.next_proposal_id += 1;
        Ok(id)
    }

    pub fn find_proposal_mut(&mut self, id: u64) -> Option<&mut Proposal> {
        self.proposals.iter_mut().find(|p| p.id == id)
    }

    pub fn active_proposals(&self) -> Vec<&Proposal> {
        self.proposals
            .iter()
            .filter(|p| p.status == ProposalStatus::Active)
            .collect()
    }

    /// V71: Cancel a proposal. Only the original proposer can cancel.
    /// The proposal must still be Active.
    pub fn cancel_proposal(&mut self, proposal_id: u64, caller: &Address) -> Result<(), String> {
        let proposal = self
            .proposals
            .iter_mut()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| format!("Proposal {} not found", proposal_id))?;

        if proposal.proposer != *caller {
            return Err("Only the proposer can cancel the proposal".into());
        }
        if proposal.status != ProposalStatus::Active {
            return Err("Proposal is not active".into());
        }

        proposal.status = ProposalStatus::Failed;
        Ok(())
    }

    /// P5 ADIM11 Bulgu 33+Governance: Execute all passed-but-not-yet-executed
    /// proposals. Returns a list of executed proposal IDs and their actions
    /// for the caller to apply state changes.
    ///
    /// This method ONLY transitions status from Passed → Executed.
    /// The actual state mutations (whitelist/dewhitelist) are returned
    /// as GovernanceAction enums for the executor/blockchain to apply.
    pub fn execute_passed_proposals(&mut self) -> Vec<GovernanceAction> {
        let mut actions = Vec::new();
        for proposal in &mut self.proposals {
            if proposal.status != ProposalStatus::Passed {
                continue;
            }
            let action = match &proposal.p_type {
                ProposalType::WhitelistVerifier { address } => {
                    Some(GovernanceAction::WhitelistVerifier(*address))
                }
                ProposalType::DewhitelistVerifier { address } => {
                    Some(GovernanceAction::DewhitelistVerifier(*address))
                }
                ProposalType::SetEncryptionPolicy(policy) => {
                    Some(GovernanceAction::SetEncryptionPolicy(policy.clone()))
                }
                ProposalType::SetConstitutionParameter(parameter) => Some(
                    GovernanceAction::SetConstitutionParameter(parameter.clone()),
                ),
                _ => None, // Other proposal types: no auto-execution yet
            };
            if let Some(a) = action {
                proposal.status = ProposalStatus::Executed;
                actions.push(a);
            }
        }
        actions
    }
}

/// P5 ADIM11 Bulgu 33+Governance: Actions produced by governance proposal
/// execution. The executor applies these to the AI registry state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceAction {
    WhitelistVerifier(Address),
    DewhitelistVerifier(Address),
    SetEncryptionPolicy(crate::pollen::EncryptionPolicy),
    SetConstitutionParameter(ConstitutionParameter),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::core::constitution::{ConstitutionParameterKey, ConstitutionValue};

    #[test]
    fn governance_execute_passed_proposals_whitelist() {
        let mut gov = GovernanceState::default();
        let verifier = Address::from([0xAA; 32]);
        let proposer = Address::from([0x01; 32]);

        // Create and pass a WhitelistVerifier proposal
        gov.create_proposal(
            proposer,
            ProposalType::WhitelistVerifier { address: verifier },
            0,
            10,
        )
        .unwrap();

        // Vote to pass (add enough stake)
        let proposal = gov.find_proposal_mut(0).unwrap();
        proposal.add_vote(proposer, 100_000, true, 0).unwrap();
        proposal.status = ProposalStatus::Passed; // simulate passage

        let actions = gov.execute_passed_proposals();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], GovernanceAction::WhitelistVerifier(verifier));

        // Proposal should now be Executed
        let p = gov.find_proposal_mut(0).unwrap();
        assert_eq!(p.status, ProposalStatus::Executed);
    }

    #[test]
    fn governance_execute_passed_proposals_dewhitelist() {
        let mut gov = GovernanceState::default();
        let verifier = Address::from([0xBB; 32]);
        let proposer = Address::from([0x01; 32]);

        gov.create_proposal(
            proposer,
            ProposalType::DewhitelistVerifier { address: verifier },
            0,
            10,
        )
        .unwrap();

        let proposal = gov.find_proposal_mut(0).unwrap();
        proposal.add_vote(proposer, 100_000, true, 0).unwrap();
        proposal.status = ProposalStatus::Passed;

        let actions = gov.execute_passed_proposals();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], GovernanceAction::DewhitelistVerifier(verifier));
    }

    #[test]
    fn governance_no_action_for_non_verifier_proposals() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);

        gov.create_proposal(proposer, ProposalType::ChangeBaseFee(500), 0, 10)
            .unwrap();

        let proposal = gov.find_proposal_mut(0).unwrap();
        proposal.status = ProposalStatus::Passed;

        let actions = gov.execute_passed_proposals();
        assert!(
            actions.is_empty(),
            "ChangeBaseFee should not produce governance actions"
        );
    }

    #[test]
    fn governance_rejects_invalid_encryption_policy_proposal() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);
        let invalid = crate::pollen::EncryptionPolicy {
            version: 1,
            hpke_suite_id: 0x20,
            min_public_key_bytes: 32,
            max_grant_duration_blocks: 0,
            deprecated_after_block: None,
            active: true,
        };
        let err = gov
            .create_proposal(proposer, ProposalType::SetEncryptionPolicy(invalid), 0, 10)
            .unwrap_err();
        assert!(err.contains("max_grant_duration"));
    }

    #[test]
    fn governance_executes_encryption_policy_action() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);
        let policy = crate::pollen::EncryptionPolicy {
            version: 1,
            hpke_suite_id: 0x20,
            min_public_key_bytes: 32,
            max_grant_duration_blocks: 100,
            deprecated_after_block: None,
            active: true,
        };
        gov.create_proposal(
            proposer,
            ProposalType::SetEncryptionPolicy(policy.clone()),
            0,
            10,
        )
        .unwrap();
        let proposal = gov.find_proposal_mut(0).unwrap();
        proposal.add_vote(proposer, 100_000, true, 0).unwrap();
        proposal.status = ProposalStatus::Passed;
        let actions = gov.execute_passed_proposals();
        assert_eq!(actions, vec![GovernanceAction::SetEncryptionPolicy(policy)]);
    }

    #[test]
    fn governance_rejects_constitution_guardrail_disable() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);
        let update = ConstitutionParameter::new(
            ConstitutionParameterKey::NoGovernanceReadOverride,
            ConstitutionValue::Bool(false),
            10,
            [1u8; 32],
        );
        let err = gov
            .create_proposal(
                proposer,
                ProposalType::SetConstitutionParameter(update),
                0,
                10,
            )
            .unwrap_err();
        assert!(err.contains("cannot be disabled"));
    }

    #[test]
    fn governance_executes_bounded_constitution_parameter_action() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);
        let update = ConstitutionParameter::new(
            ConstitutionParameterKey::MaxEmergencyHaltEpochs,
            ConstitutionValue::U64(720),
            11,
            [2u8; 32],
        );
        gov.create_proposal(
            proposer,
            ProposalType::SetConstitutionParameter(update.clone()),
            0,
            10,
        )
        .unwrap();
        let proposal = gov.find_proposal_mut(0).unwrap();
        proposal.add_vote(proposer, 100_000, true, 0).unwrap();
        proposal.status = ProposalStatus::Passed;
        let actions = gov.execute_passed_proposals();
        assert_eq!(
            actions,
            vec![GovernanceAction::SetConstitutionParameter(update)]
        );
    }

    #[test]
    fn phase11_16_governance_rejects_non_whitelisted_parameter_proposal() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);
        let err = gov
            .create_proposal(
                proposer,
                ProposalType::ParameterUpdate("code_upgrade".into(), "v2".into()),
                0,
                10,
            )
            .unwrap_err();
        assert!(err.contains("not whitelisted"));
    }

    #[test]
    fn phase11_16_governance_rejects_invalid_parameter_value() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);
        let err = gov
            .create_proposal(
                proposer,
                ProposalType::ParameterUpdate("min_stake".into(), "1".into()),
                0,
                10,
            )
            .unwrap_err();
        assert!(err.contains("min_stake"));
    }

    #[test]
    fn phase11_16_governance_sets_parameter_activation_timelock() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);
        let id = gov
            .create_proposal(
                proposer,
                ProposalType::ParameterUpdate("min_stake".into(), "5000".into()),
                7,
                10,
            )
            .unwrap();
        let proposal = gov.find_proposal_mut(id).unwrap();
        assert_eq!(proposal.end_epoch, 17);
        assert_eq!(
            proposal.activation_epoch,
            Some(17 + GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS)
        );
        assert!(!proposal.activation_ready(26));
        assert!(proposal.activation_ready(27));
    }

    #[test]
    fn phase11_16_governance_records_vote_weight_snapshot() {
        let proposer = Address::from([0x01; 32]);
        let voter = Address::from([0x02; 32]);
        let mut proposal = Proposal::new(
            7,
            proposer,
            ProposalType::ParameterUpdate("min_stake".into(), "5000".into()),
            0,
            10,
        );
        proposal.add_vote(voter, 1_000, true, 0).unwrap();
        assert_eq!(proposal.votes_for, 1_000);
        assert_eq!(proposal.vote_weight_of(&voter), 1_000);
        assert!(proposal.add_vote(voter, 1_000, true, 0).is_err());
    }

    #[test]
    fn phase11_16_governance_stake_transfer_cannot_double_count_vote_weight() {
        let proposer = Address::from([0x01; 32]);
        let voter = Address::from([0x02; 32]);
        let mut proposal = Proposal::new(
            8,
            proposer,
            ProposalType::ParameterUpdate("min_stake".into(), "5000".into()),
            0,
            10,
        );
        proposal.add_vote(voter, 1_000, true, 0).unwrap();

        proposal.reduce_vote_weight(&voter, 400);
        assert_eq!(proposal.votes_for, 600);
        assert_eq!(proposal.vote_weight_of(&voter), 600);

        proposal.reduce_vote_weight(&voter, 10_000);
        assert_eq!(proposal.votes_for, 0);
        assert_eq!(proposal.vote_weight_of(&voter), 0);
        assert!(proposal.add_vote(voter, 1_000, true, 0).is_err());
    }
}
