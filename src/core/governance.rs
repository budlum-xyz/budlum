use crate::core::address::Address;
use crate::core::constitution::{ConstitutionParameter, ConstitutionRegistry};
use crate::registry::params::RegistryParams;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Accepted parameter proposals activate after this delay.
pub const GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS: u64 = 10;

/// Activation delay for proposals that change what the chain enforces about
/// itself, rather than a tunable number.
///
/// Longer than the parameter delay because the blast radius is larger: an
/// encryption policy, a constitution parameter or an unfrozen domain changes
/// the rules other checks are written against, and an operator who disagrees
/// needs time to react before it takes effect.
pub const GOVERNANCE_POLICY_ACTIVATION_DELAY_EPOCHS: u64 = 20;

/// Activation delay for proposals that take stake or verifier standing away
/// from a specific account.
///
/// Shorter than the policy delay: slashing evidence is time-sensitive, and a
/// long window lets a proven equivocator keep signing. Still non-zero, because
/// a governance slash names one account and the accused needs a window in
/// which the decision can be seen and contested.
pub const GOVERNANCE_TARGETED_ACTION_DELAY_EPOCHS: u64 = 5;

/// A zero activation delay is not a timelock.
///
/// Enforced at compile time rather than in a test: a test asserting on
/// constants is a constant assertion, and the point is that nobody can set one
/// of these to zero in the first place. Two 2026 incidents turned on exactly
/// this value being zero when it mattered.
const _: () = {
    assert!(GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS > 0);
    assert!(GOVERNANCE_POLICY_ACTIVATION_DELAY_EPOCHS > 0);
    assert!(GOVERNANCE_TARGETED_ACTION_DELAY_EPOCHS > 0);
    // A rule that changes what the chain enforces waits longer than one that
    // moves a number.
    assert!(
        GOVERNANCE_POLICY_ACTIVATION_DELAY_EPOCHS > GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS
    );
};

/// How long an accepted proposal of this kind waits before it can be applied.
///
/// Exhaustive on purpose: a new `ProposalType` will not compile until someone
/// decides which delay it belongs in. The previous code used
/// `matches!(.., ParameterUpdate(..))`, so every variant added after it
/// silently inherited a zero delay.
#[must_use]
pub const fn activation_delay_epochs(p_type: &ProposalType) -> u64 {
    match p_type {
        // Tunable numbers and parameter strings.
        ProposalType::ChangeBaseFee(_)
        | ProposalType::ChangeBlockReward(_)
        | ProposalType::ParameterUpdate(_, _) => GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS,

        // Rules the rest of the system is written against.
        ProposalType::VerifyHubApp { .. }
        | ProposalType::SetEncryptionPolicy(_)
        | ProposalType::SetConstitutionParameter(_)
        | ProposalType::UnfreezeConsensusDomain { .. } => GOVERNANCE_POLICY_ACTIVATION_DELAY_EPOCHS,

        // Actions aimed at one account.
        ProposalType::SlashValidator { .. }
        | ProposalType::WhitelistVerifier { .. }
        | ProposalType::DewhitelistVerifier { .. } => GOVERNANCE_TARGETED_ACTION_DELAY_EPOCHS,
    }
}

/// Minimal on-chain governance is parameter-only and whitelist-bound.
pub const GOVERNANCE_PARAMETER_WHITELIST: &[&str] = &[
    "min_stake",
    "unbonding_epochs",
    "double_sign_slash_ratio_fixed",
    "liveness_slash_ratio_fixed",
    "malicious_slash_ratio_fixed",
    "bridge_relayer_fee_ppm",
    "bridge_relayer_min_fee",
    "max_invalid_votes_per_epoch",
    "transfer_fee_ppm",
    "swap_fee_ppm",
    "bridge_fee_ppm",
    "ai_model_register_fee",
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
        "bridge_relayer_fee_ppm" => {
            params.bridge_relayer_fee_ppm = value
                .parse()
                .map_err(|e| format!("invalid bridge_relayer_fee_ppm: {e}"))?;
        }
        "bridge_relayer_min_fee" => {
            params.bridge_relayer_min_fee = value
                .parse()
                .map_err(|e| format!("invalid bridge_relayer_min_fee: {e}"))?;
        }
        "max_invalid_votes_per_epoch" => {
            params.max_invalid_votes_per_epoch = value
                .parse::<u64>()
                .map_err(|e| format!("invalid max_invalid_votes_per_epoch: {e}"))?;
        }
        "transfer_fee_ppm" => {
            params.transfer_fee_ppm = value
                .parse::<u64>()
                .map_err(|e| format!("invalid transfer_fee_ppm: {e}"))?;
        }
        "swap_fee_ppm" => {
            params.swap_fee_ppm = value
                .parse::<u64>()
                .map_err(|e| format!("invalid swap_fee_ppm: {e}"))?;
        }
        "bridge_fee_ppm" => {
            params.bridge_fee_ppm = value
                .parse::<u64>()
                .map_err(|e| format!("invalid bridge_fee_ppm: {e}"))?;
        }
        "malicious_slash_ratio_fixed" => {
            params.malicious_slash_ratio_fixed = value
                .parse::<u64>()
                .map_err(|e| format!("invalid malicious_slash_ratio_fixed: {e}"))?;
        }
        "ai_model_register_fee" => {
            params.ai_model_register_fee = value
                .parse::<u64>()
                .map_err(|e| format!("invalid ai_model_register_fee: {e}"))?;
        }
        // The whitelist is checked above, but a name added there and not
        // here must refuse the proposal rather than take the node down inside
        // `create_proposal` (that is how `ai_model_register_fee` panicked).
        other => return Err(format!("governance parameter has no validator: {other}")),
    }
    params.validate()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalType {
    ChangeBaseFee(u64),
    ChangeBlockReward(u64),
    SlashValidator {
        address: Address,
        /// Hash of the slashing evidence that proves misbehavior.
        /// Governance slash now requires cryptographic proof, not just a vote.
        evidence_hash: [u8; 32],
    },
    ParameterUpdate(String, String),
    /// Whitelist a verifier via governance vote.
    /// Enables decentralized, vote-based verifier onboarding.
    WhitelistVerifier {
        address: Address,
    },
    /// Remove a verifier from the whitelist.
    DewhitelistVerifier {
        address: Address,
    },
    /// DAO-managed encryption parameters for Pollen/B.U.D.
    /// This is parameter-only governance: no decrypt/key/read override exists.
    SetEncryptionPolicy(crate::pollen::EncryptionPolicy),
    /// Constitution Engine parameter update. Hard guardrails are
    /// Validated fail-closed and cannot be weakened by governance.
    SetConstitutionParameter(ConstitutionParameter),
    /// Governance-controlled domain unfreeze
    /// - domain_id: target consensus domain to unfreeze
    /// - expected_validator_set_hash: 32-byte hash that must match current domain's validator_set_hash (anti-grind / anti-replay binding)
    /// - justification_hash: hash of frozen reason / evidence reference (e.g., hash of audit report / governance forum post)
    ///
    /// Anti-replay: proposal id itself is unique and executed only once (Passed->Executed).
    /// Award the governance verification badge to a `budlum.xyz` app.
    ///
    /// Distinct from `BudlumxyzAttestApp`, which is the developer's own
    /// ownership claim. This one is the audited badge, and it moves only
    /// through a vote because the whole point of `verified` is that somebody
    /// other than the developer stood behind it.
    ///
    /// `AppRecord.verified` was hashed into the state root from the start and
    /// no path could set it, so it was permanently false. This is the path.
    /// The proposal binds the reviewed snapshot: the developer address, the
    /// manifest id and the website-url hash that voters evaluated. A passed
    /// vote may not be retargeted to different content (HIGH, CWE-345;
    /// BUDLUM finding #173).
    VerifyHubApp {
        app_id: u64,
        developer: crate::core::address::Address,
        manifest_id: Option<crate::storage::content_id::ContentId>,
        website_url_hash: [u8; 32],
    },
    UnfreezeConsensusDomain {
        domain_id: u32,
        expected_validator_set_hash: [u8; 32],
        justification_hash: [u8; 32],
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
    /// Address -> vote (true = for). Ordered because `GovernanceState::root`
    /// hashes the serialized proposals: a hash map would iterate in a
    /// per-process order and two nodes would disagree on the state root.
    pub voters: BTreeMap<Address, bool>,
    /// Vote-weight snapshot captured when each validator votes.
    #[serde(default)]
    pub voter_weights: BTreeMap<Address, u64>,
    /// Optional delayed activation epoch after a proposal passes.
    #[serde(default)]
    pub activation_epoch: Option<u64>,
}

/// Stand-in bytes hashed when a governance record cannot be serialized.
///
/// Cannot fire for these derived-`Serialize` owned types. Kept non-panicking
/// because the call site computes a governance root shared by every node.
const GOVERNANCE_SERIALIZE_FAILED: &[u8] = b"budlum/serialize-failed/governance";

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
            voters: BTreeMap::new(),
            voter_weights: BTreeMap::new(),
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
        // Voting window closed after end_epoch (pairs with finalize gate).
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

    /// Reduce only the stake weight originally snapshotted for a voter.
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

    /// Finalize proposal - now requires current_epoch >= end_epoch.
    /// Previously, finalize could be called at any time, allowing early-finalize
    /// Attacks where a proposal with sufficient votes could be forced through
    /// Before the voting period ended.
    pub fn finalize(&mut self, total_stake: u64, quorum_pct: u64, current_epoch: u64) {
        if self.status != ProposalStatus::Active {
            return;
        }
        // Voting period must have elapsed before finalization
        if current_epoch < self.end_epoch {
            return;
        }
        // Use u128 to prevent overflow in the quorum calculation
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
    /// Per-proposer current-epoch proposal count.
    /// Key: (proposer_address, epoch). Value: accepted proposals submitted.
    /// The next proposal costs `2^count` times base fee; old epochs are pruned.
    #[serde(default, with = "proposer_epoch_count_as_seq")]
    pub proposer_epoch_count: std::collections::BTreeMap<(Address, u64), u64>,
}

mod proposer_epoch_count_as_seq {
    use super::Address;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::BTreeMap;

    #[derive(Serialize, Deserialize)]
    struct Entry {
        proposer: Address,
        epoch: u64,
        count: u64,
    }

    pub fn serialize<S>(
        map: &BTreeMap<(Address, u64), u64>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<Entry> = map
            .iter()
            .map(|((proposer, epoch), count)| Entry {
                proposer: *proposer,
                epoch: *epoch,
                count: *count,
            })
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<BTreeMap<(Address, u64), u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries = Vec::<Entry>::deserialize(deserializer)?;
        Ok(entries
            .into_iter()
            .map(|entry| ((entry.proposer, entry.epoch), entry.count))
            .collect())
    }
}

impl GovernanceState {
    pub fn has_non_default_state(&self) -> bool {
        !self.proposals.is_empty()
            || self.next_proposal_id != 0
            || !self.proposer_epoch_count.is_empty()
            || self.constitution.has_non_default_updates()
    }

    pub fn root(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"BDLM_GOVERNANCE_STATE_V1");
        hasher.update(self.next_proposal_id.to_le_bytes());
        hasher.update(
            bincode::serialize(&self.proposals)
                .unwrap_or_else(|_| GOVERNANCE_SERIALIZE_FAILED.to_vec()),
        );
        hasher.update(self.constitution.root());
        hasher.update(
            bincode::serialize(&self.proposer_epoch_count)
                .unwrap_or_else(|_| GOVERNANCE_SERIALIZE_FAILED.to_vec()),
        );
        hasher.finalize().into()
    }

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
            ProposalType::VerifyHubApp {
                app_id,
                developer,
                manifest_id,
                website_url_hash,
            } => {
                // Existence is checked at execution, not here: an app can be
                // registered while the vote is open, and refusing at proposal
                // time would make the outcome depend on submission order.
                // The reviewed snapshot is bound here so the badge cannot be
                // retargeted later (HIGH, CWE-345).
                let _ = (app_id, developer, manifest_id, website_url_hash);
            }
            ProposalType::SetEncryptionPolicy(policy) => policy.validate()?,
            ProposalType::SetConstitutionParameter(parameter) => parameter.validate_update()?,
            ProposalType::UnfreezeConsensusDomain {
                domain_id,
                expected_validator_set_hash,
                justification_hash,
            } => {
                if *domain_id == 0 {
                    return Err("UnfreezeConsensusDomain domain_id 0 is reserved".into());
                }
                if expected_validator_set_hash == &[0u8; 32] {
                    return Err(
                        "UnfreezeConsensusDomain expected_validator_set_hash must be non-zero"
                            .into(),
                    );
                }
                if justification_hash == &[0u8; 32] {
                    return Err(
                        "UnfreezeConsensusDomain justification_hash must be non-zero".into(),
                    );
                }
            }
            _ => {}
        }

        // Validate proposal duration
        const MIN_PROPOSAL_DURATION: u64 = 10; // Minimum 10 epochs
        const MAX_PROPOSAL_DURATION: u64 = 100_000; // Maximum 100,000 epochs
        if !(MIN_PROPOSAL_DURATION..=MAX_PROPOSAL_DURATION).contains(&duration) {
            return Err(format!(
                "Proposal duration must be between {} and {} epochs",
                MIN_PROPOSAL_DURATION, MAX_PROPOSAL_DURATION
            ));
        }

        // Limit active proposals to prevent state bloat
        const MAX_ACTIVE_PROPOSALS: usize = 100;
        let active_count = self
            .proposals
            .iter()
            .filter(|p| p.status == ProposalStatus::Active)
            .count();
        if active_count >= MAX_ACTIVE_PROPOSALS {
            return Err("Too many active proposals".into());
        }

        // Proposal bandwidth is fee-gated, not hard-capped per proposer. Keep
        // Only the current/future epoch counters so the fee schedule itself does
        // Not become an unbounded consensus map.
        self.proposer_epoch_count
            .retain(|(_, epoch), _| *epoch >= current_epoch);

        let end_epoch = current_epoch
            .checked_add(duration)
            .ok_or_else(|| "Proposal end_epoch overflow".to_string())?;

        let id = self.next_proposal_id;
        let mut proposal = Proposal::new(id, proposer, p_type, current_epoch, duration);
        // Every proposal type gets a delay.
        //
        // Only `ParameterUpdate` used to. The other eight fell through to
        // `activation_epoch()`'s `unwrap_or(self.end_epoch)`, so they executed
        // the moment voting closed - including `SlashValidator`,
        // `SetConstitutionParameter` and `UnfreezeConsensusDomain`, which are
        // the ones worth watching.
        //
        // A delay is what turns a passed vote into something observable before
        // it binds. Without it, the first time anyone learns a domain was
        // unfrozen is when it is already unfrozen.
        proposal.activation_epoch = Some(
            end_epoch
                .checked_add(activation_delay_epochs(&proposal.p_type))
                .ok_or_else(|| "Proposal activation_epoch overflow".to_string())?,
        );
        self.proposals.push(proposal);
        self.next_proposal_id += 1;
        // Increment only after proposal creation succeeds; the next submission
        // Observes the escalated fee multiplier.
        let count = self
            .proposer_epoch_count
            .entry((proposer, current_epoch))
            .or_insert(0);
        *count += 1;
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

    /// Cancel a proposal. Only the original proposer can cancel.
    /// The proposal must still be Active.
    /// Fee multiplier for the proposer's next submission in this epoch.
    /// With `count` already accepted proposals, next cost is `2^count`:
    /// First = 1x, second = 2x, third = 4x. Overflow saturates fail-closed.
    pub fn proposal_fee_multiplier(&self, proposer: &Address, current_epoch: u64) -> u64 {
        let count = self
            .proposer_epoch_count
            .get(&(*proposer, current_epoch))
            .copied()
            .unwrap_or(0);
        u32::try_from(count)
            .ok()
            .and_then(|shift| 1u64.checked_shl(shift))
            .unwrap_or(u64::MAX)
    }

    pub fn cancel_proposal(&mut self, proposal_id: u64, caller: &Address) -> Result<(), String> {
        let proposal = self
            .proposals
            .iter_mut()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| format!("Proposal {proposal_id} not found"))?;

        if proposal.proposer != *caller {
            return Err("Only the proposer can cancel the proposal".into());
        }
        if proposal.status != ProposalStatus::Active {
            return Err("Proposal is not active".into());
        }

        proposal.status = ProposalStatus::Failed;
        Ok(())
    }

    /// Execute all passed-but-not-yet-executed
    /// Proposals. Returns a list of executed proposal IDs and their actions
    /// For the caller to apply state changes.
    ///
    /// This method ONLY transitions status from Passed → Executed.
    /// The actual state mutations (whitelist/dewhitelist) are returned
    /// As GovernanceAction enums for the executor/blockchain to apply.
    ///
    /// A passed proposal is executed only once its activation delay has
    /// elapsed at `current_epoch`. The delay is the same one `advance_epoch`
    /// honours, so no caller can turn a fresh vote into state early.
    pub fn execute_passed_proposals(&mut self, current_epoch: u64) -> Vec<GovernanceAction> {
        let mut actions = Vec::new();
        for proposal in &mut self.proposals {
            if proposal.status != ProposalStatus::Passed
                || !proposal.activation_ready(current_epoch)
            {
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
                ProposalType::UnfreezeConsensusDomain {
                    domain_id,
                    expected_validator_set_hash,
                    justification_hash,
                } => Some(GovernanceAction::UnfreezeConsensusDomain {
                    domain_id: *domain_id,
                    expected_validator_set_hash: *expected_validator_set_hash,
                    justification_hash: *justification_hash,
                }),
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

/// Actions produced by governance proposal
/// Execution. The executor applies these to the AI registry state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceAction {
    WhitelistVerifier(Address),
    DewhitelistVerifier(Address),
    SetEncryptionPolicy(crate::pollen::EncryptionPolicy),
    SetConstitutionParameter(ConstitutionParameter),
    VerifyHubApp {
        app_id: u64,
    },
    UnfreezeConsensusDomain {
        domain_id: u32,
        expected_validator_set_hash: [u8; 32],
        justification_hash: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::address::Address;
    use crate::core::constitution::{ConstitutionParameterKey, ConstitutionValue};

    /// Every whitelisted name must reach a real arm: a `u64` probe either
    /// passes or fails on bounds, never on "no validator" and never by panic.
    #[test]
    fn every_whitelisted_parameter_has_a_validator_arm() {
        for key in GOVERNANCE_PARAMETER_WHITELIST {
            let err = validate_governance_parameter_update(key, "1000").err();
            assert!(
                !err.as_deref()
                    .is_some_and(|e| e.contains("has no validator")),
                "{key} is whitelisted but validate_governance_parameter_update \
                 has no arm for it: {err:?}"
            );
        }
        assert_eq!(
            validate_governance_parameter_update("ai_model_register_fee", "25"),
            Ok(())
        );
        assert!(validate_governance_parameter_update("ai_model_register_fee", "x").is_err());
    }

    /// The governance root is part of the state root, so it must not depend
    /// on the order in which voters were inserted.
    #[test]
    fn governance_root_is_insertion_order_independent() {
        let voters: Vec<Address> = (1u8..=12).map(|b| Address::from([b; 32])).collect();
        let build = |order: &[Address]| {
            let mut gov = GovernanceState::default();
            let id = gov
                .create_proposal(
                    voters[0],
                    ProposalType::ParameterUpdate("min_stake".into(), "2000".into()),
                    0,
                    10,
                )
                .unwrap();
            let p = gov.find_proposal_mut(id).unwrap();
            for (i, v) in order.iter().enumerate() {
                p.add_vote(*v, 100 + i as u64, i % 2 == 0, 1).unwrap();
            }
            gov.root()
        };
        let mut reversed = voters.clone();
        reversed.reverse();
        assert_eq!(build(&voters), build(&reversed));
    }

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

        let actions = gov.execute_passed_proposals(u64::MAX);
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0], GovernanceAction::WhitelistVerifier(verifier));

        // Proposal should now be Executed
        let p = gov.find_proposal_mut(0).unwrap();
        assert_eq!(p.status, ProposalStatus::Executed);
    }

    #[test]
    fn governance_execute_passed_proposals_waits_for_activation() {
        let mut gov = GovernanceState::default();
        let verifier = Address::from([0xAB; 32]);
        let proposer = Address::from([0x01; 32]);

        gov.create_proposal(
            proposer,
            ProposalType::WhitelistVerifier { address: verifier },
            0,
            10,
        )
        .unwrap();
        let proposal = gov.find_proposal_mut(0).unwrap();
        proposal.add_vote(proposer, 100_000, true, 0).unwrap();
        proposal.status = ProposalStatus::Passed;
        let activation = proposal.activation_epoch();
        assert!(
            activation > proposal.end_epoch,
            "every type carries a delay"
        );

        // Voting closed, delay still running: nothing binds, status unchanged.
        assert!(gov
            .execute_passed_proposals(proposal_end_epoch(&gov, 0))
            .is_empty());
        assert!(gov.execute_passed_proposals(activation - 1).is_empty());
        assert_eq!(
            gov.find_proposal_mut(0).unwrap().status,
            ProposalStatus::Passed
        );

        // The activation epoch executes it exactly once.
        let actions = gov.execute_passed_proposals(activation);
        assert_eq!(actions, vec![GovernanceAction::WhitelistVerifier(verifier)]);
        assert_eq!(
            gov.find_proposal_mut(0).unwrap().status,
            ProposalStatus::Executed
        );
        assert!(gov.execute_passed_proposals(activation + 1).is_empty());
    }

    fn proposal_end_epoch(gov: &GovernanceState, id: u64) -> u64 {
        gov.proposals
            .iter()
            .find(|p| p.id == id)
            .expect("proposal exists")
            .end_epoch
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

        let actions = gov.execute_passed_proposals(u64::MAX);
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

        let actions = gov.execute_passed_proposals(u64::MAX);
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
        let actions = gov.execute_passed_proposals(u64::MAX);
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
        let actions = gov.execute_passed_proposals(u64::MAX);
        assert_eq!(
            actions,
            vec![GovernanceAction::SetConstitutionParameter(update)]
        );
    }

    #[test]
    fn governance_rejects_non_whitelisted_parameter_proposal() {
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
    fn governance_rejects_invalid_parameter_value() {
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
    fn governance_sets_parameter_activation_timelock() {
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
    fn governance_records_vote_weight_snapshot() {
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
    fn governance_stake_transfer_cannot_double_count_vote_weight() {
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

    #[test]
    fn governance_whitelist_invariant_blocks_all_non_core_params() {
        // The ADR-004 whitelist invariant: only security-critical parameters
        // can be changed; the permissionless core behaviours (code upgrade,
        // supply, fee and treasury, the validator set) can NEVER be changed.
        // This test protects the invariant by trying a non-whitelisted
        // parameter - a breaking test.
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x01; 32]);
        let non_core = [
            "code_upgrade",
            "total_supply",
            "block_reward",
            "treasury",
            "validator_set",
            "fee",
        ];
        for key in non_core {
            let err = gov
                .create_proposal(
                    proposer,
                    ProposalType::ParameterUpdate(key.to_string(), "x".to_string()),
                    0,
                    10,
                )
                .unwrap_err();
            assert!(
                err.contains("not whitelisted"),
                "non-core param '{key}' must be rejected by the whitelist invariant"
            );
        }
        // A security parameter inside the whitelist is not refused by the
        // whitelist, so there is no false positive.
        for key in [
            "min_stake",
            "unbonding_epochs",
            "double_sign_slash_ratio_fixed",
            "liveness_slash_ratio_fixed",
            "malicious_slash_ratio_fixed",
        ] {
            let res = gov.create_proposal(
                proposer,
                ProposalType::ParameterUpdate(key.to_string(), "5000".to_string()),
                0,
                10,
            );
            if let Err(e) = &res {
                assert!(
                    !e.contains("not whitelisted"),
                    "whitelisted security param '{key}' wrongly blocked by whitelist"
                );
            }
        }
    }

    #[test]
    fn governance_root_changes_when_proposal_is_created() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x0A; 32]);
        let root_before = gov.root();
        gov.create_proposal(
            proposer,
            ProposalType::ParameterUpdate("min_stake".into(), "5000".into()),
            0,
            10,
        )
        .unwrap();
        assert_ne!(root_before, gov.root());
    }

    #[test]
    fn governance_serde_roundtrip_preserves_proposer_epoch_count() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0x0B; 32]);
        gov.create_proposal(
            proposer,
            ProposalType::ParameterUpdate("min_stake".into(), "5000".into()),
            0,
            10,
        )
        .unwrap();
        let bytes = serde_json::to_vec(&gov).expect("governance must serialize");
        let decoded: GovernanceState =
            serde_json::from_slice(&bytes).expect("governance must deserialize");
        assert_eq!(decoded.next_proposal_id, 1);
        assert_eq!(decoded.proposals.len(), 1);
        assert_eq!(decoded.proposer_epoch_count.get(&(proposer, 0)), Some(&1));
    }
}

#[cfg(test)]
mod l4_tests {
    use super::*;

    #[test]
    fn l4_fee_only_policy_has_no_per_proposer_hard_cap() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0xAA; 32]);
        for i in 0..6u64 {
            let result = gov.create_proposal(proposer, ProposalType::ChangeBaseFee(100 + i), 0, 10);
            assert!(result.is_ok(), "proposal {i} should remain fee-gated");
        }
        assert_eq!(gov.proposal_fee_multiplier(&proposer, 0), 64);
    }

    #[test]
    fn l4_new_epoch_prunes_old_fee_counters() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0xBB; 32]);
        gov.create_proposal(proposer, ProposalType::ChangeBaseFee(100), 0, 10)
            .unwrap();
        assert_eq!(gov.proposal_fee_multiplier(&proposer, 0), 2);

        gov.create_proposal(proposer, ProposalType::ChangeBaseFee(200), 1, 10)
            .unwrap();
        assert!(!gov.proposer_epoch_count.contains_key(&(proposer, 0)));
        assert_eq!(gov.proposal_fee_multiplier(&proposer, 1), 2);
    }

    #[test]
    fn l4_fee_multiplier_escalates_for_next_submission() {
        let mut gov = GovernanceState::default();
        let proposer = Address::from([0xCC; 32]);
        assert_eq!(gov.proposal_fee_multiplier(&proposer, 0), 1);
        for (value, next_multiplier) in [(100, 2), (200, 4), (300, 8)] {
            gov.create_proposal(proposer, ProposalType::ChangeBaseFee(value), 0, 10)
                .unwrap();
            assert_eq!(gov.proposal_fee_multiplier(&proposer, 0), next_multiplier);
        }
    }

    /// Every proposal type waits before it binds.
    ///
    /// Only `ParameterUpdate` used to. The rest fell through to
    /// `activation_epoch()`'s `unwrap_or(self.end_epoch)` and executed the
    /// moment voting closed. Measured with a canary before the fix:
    ///
    ///     ChangeBaseFee          delay=0
    ///     ChangeBlockReward      delay=0
    ///     SlashValidator         delay=0
    ///     ParameterUpdate        delay=10
    ///     WhitelistVerifier      delay=0
    ///     DewhitelistVerifier    delay=0
    ///
    /// A zero delay on a governance action is what turned two 2026 incidents
    /// into drains rather than near-misses: there was no window in which a
    /// passed vote could be seen before it bound.
    #[test]
    fn no_proposal_type_activates_the_moment_voting_closes() {
        let proposer = Address::from([0x01; 32]);
        let every_type = [
            ProposalType::ChangeBaseFee(1),
            ProposalType::ChangeBlockReward(1),
            ProposalType::SlashValidator {
                address: Address::from([0x02; 32]),
                evidence_hash: [0u8; 32],
            },
            ProposalType::ParameterUpdate("min_stake".into(), "5000".into()),
            ProposalType::WhitelistVerifier {
                address: Address::from([0x03; 32]),
            },
            ProposalType::DewhitelistVerifier {
                address: Address::from([0x04; 32]),
            },
        ];

        for p_type in every_type {
            let label = format!("{p_type:?}");
            let mut gov = GovernanceState::default();
            let id = gov
                .create_proposal(proposer, p_type, 7, 10)
                .unwrap_or_else(|e| panic!("{label} must be proposable: {e}"));
            let proposal = gov.find_proposal_mut(id).expect("proposal exists");
            let end = proposal.end_epoch;
            let activation = proposal.activation_epoch();

            assert!(
                activation > end,
                "{label} activates at {activation}, the same epoch voting ends \
                 ({end}) - there is no window to observe it"
            );
            assert!(
                !proposal.activation_ready(end),
                "{label} is ready to execute the epoch voting closes"
            );
            assert!(
                proposal.activation_ready(activation),
                "{label} must be executable once its delay has passed"
            );
        }
    }

    /// The delay is chosen by kind, not left to a default.
    #[test]
    fn each_delay_class_is_what_it_claims() {
        assert_eq!(
            activation_delay_epochs(&ProposalType::ParameterUpdate("k".into(), "v".into())),
            GOVERNANCE_PARAMETER_ACTIVATION_DELAY_EPOCHS
        );
        assert_eq!(
            activation_delay_epochs(&ProposalType::UnfreezeConsensusDomain {
                domain_id: 1,
                expected_validator_set_hash: [0u8; 32],
                justification_hash: [0u8; 32],
            }),
            GOVERNANCE_POLICY_ACTIVATION_DELAY_EPOCHS
        );
        assert_eq!(
            activation_delay_epochs(&ProposalType::SlashValidator {
                address: Address::from([0x02; 32]),
                evidence_hash: [0u8; 32],
            }),
            GOVERNANCE_TARGETED_ACTION_DELAY_EPOCHS
        );
    }
}
