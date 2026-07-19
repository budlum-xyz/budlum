use crate::core::address::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
        }
    }

    pub fn add_vote(&mut self, voter: Address, stake: u64, vote_for: bool) -> Result<(), String> {
        if self.status != ProposalStatus::Active {
            return Err("Proposal is not active".into());
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
        Ok(())
    }

    pub fn finalize(&mut self, total_stake: u64, quorum_pct: u64) {
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
}

impl GovernanceState {
    pub fn create_proposal(
        &mut self,
        proposer: Address,
        p_type: ProposalType,
        current_epoch: u64,
        duration: u64,
    ) -> Result<u64, String> {
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

        let id = self.next_proposal_id;
        let proposal = Proposal::new(id, proposer, p_type, current_epoch, duration);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;

    #[test]
    fn governance_execute_passed_proposals_whitelist() {
        let mut gov = GovernanceState {
            proposals: Vec::new(),
            next_proposal_id: 0,
        };
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
        proposal.add_vote(proposer, 100_000, true).unwrap();
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
        let mut gov = GovernanceState {
            proposals: Vec::new(),
            next_proposal_id: 0,
        };
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
        proposal.add_vote(proposer, 100_000, true).unwrap();
        proposal.status = ProposalStatus::Passed;

        let actions = gov.execute_passed_proposals();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], GovernanceAction::DewhitelistVerifier(verifier));
    }

    #[test]
    fn governance_no_action_for_non_verifier_proposals() {
        let mut gov = GovernanceState {
            proposals: Vec::new(),
            next_proposal_id: 0,
        };
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
}
