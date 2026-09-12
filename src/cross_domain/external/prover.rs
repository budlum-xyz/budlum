//! The prover role: who carries external evidence in, what they are paid, and
//! what they lose when they lie.
//!
//! # The incentive problem
//!
//! Somebody has to watch the external chain and bring its proofs here. That
//! work costs money - a full node, bandwidth, a prover for the ZK case - and
//! the person doing it is not paid by the external chain, which has never
//! heard of us.
//!
//! A fee alone does not solve it. A prover paid per attestation is paid the
//! same whether the attestation is true or false, and a false one is cheaper
//! to produce. So the payment has to be small relative to what is at risk, and
//! the risk has to be real: the prover posts a bond, the bond is slashed when
//! an accepted attestation is contradicted, and the slashing is triggered by a
//! fraud proof anybody can submit.
//!
//! # What the bond has to cover
//!
//! Not the fee - the *value routed*. A domain carrying ten tokens needs a
//! different bond from one carrying ten thousand, and a fixed bond would mean
//! the large domain is under-collateralised while the small one is
//! over-collateralised into unprofitability. [`required_bond_atoms`] therefore
//! scales with the declared routing ceiling, and the ceiling is part of what
//! the domain registers, so raising it is a visible act.
//!
//! # What this module deliberately does not do
//!
//! It does not rank provers, blacklist them, or compute a reputation. A prover
//! that has been slashed is still allowed to post a bond and try again: the
//! bond is the mechanism, and a second mechanism that quietly overrides it is
//! how a permissionless registration becomes a permissioned one.

use crate::core::address::Address;
use serde::{Deserialize, Serialize};

/// A prover's standing with one domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverBond {
    pub prover: Address,
    pub bond_atoms: u128,
    /// The routing ceiling this bond was posted against. If the domain raises
    /// its ceiling, every bond below the new requirement stops being
    /// sufficient - see [`ProverBond::is_sufficient`].
    pub ceiling_atoms: u128,
    /// Cumulative atoms taken from this bond by slashing. Kept so a bond's
    /// history is readable; a bond that was slashed and topped back up is a
    /// different fact from one that never was.
    pub slashed_atoms: u128,
    /// Slashing events, kept forever.
    pub slashings: Vec<Slashing>,
    /// Attestations this prover carried that were accepted.
    pub accepted: u64,
    /// Attestations this prover carried that were refused.
    pub refused: u64,
}

/// One slashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Slashing {
    pub at_height: u64,
    /// The evidence digest that was contradicted.
    pub evidence_digest: [u8; 32],
    pub amount_atoms: u128,
    /// Who submitted the fraud proof, and what they were paid for it.
    pub challenger: Address,
    pub challenge_reward_atoms: u128,
}

impl ProverBond {
    /// Whether this bond still covers the domain's current ceiling.
    ///
    /// Checked against the *live* bond, not the posted one: a slashed bond
    /// that was never topped up is not covering anything, and treating it as
    /// sufficient would be the bug this whole module exists to prevent.
    #[must_use]
    pub fn is_sufficient(&self, current_ceiling_atoms: u128) -> bool {
        self.bond_atoms >= required_bond_atoms(current_ceiling_atoms, BOND_RATIO_NUM, BOND_RATIO_DEN)
    }

    /// The live bond: what is actually there to lose.
    #[must_use]
    pub fn live_atoms(&self) -> u128 {
        self.bond_atoms
    }

    /// Applies a slashing. Returns the amount actually taken, which may be
    /// less than requested if the bond is smaller than the penalty - a prover
    /// cannot lose more than they posted, and pretending otherwise would make
    /// the accounting lie.
    pub fn slash(&mut self, at_height: u64, evidence_digest: [u8; 32], want_atoms: u128, challenger: Address, challenge_reward_atoms: u128) -> u128 {
        let taken = self.bond_atoms.min(want_atoms);
        self.bond_atoms = self.bond_atoms.saturating_sub(taken);
        self.slashed_atoms = self.slashed_atoms.saturating_add(taken);
        self.slashings.push(Slashing {
            at_height,
            evidence_digest,
            amount_atoms: taken,
            challenger,
            challenge_reward_atoms,
        });
        taken
    }
}

/// The bond ratio, as a pair. The denominator is a power of ten so the
/// arithmetic is exact in integers: a percentage stored as a float would make
/// two nodes computing the same requirement disagree in the last digit, and a
/// bond requirement that differs between nodes is a fork.
pub const BOND_RATIO_NUM: u128 = 1;
pub const BOND_RATIO_DEN: u128 = 10;

/// The bond required to carry a domain whose routing ceiling is
/// `ceiling_atoms`.
///
/// Saturating rather than wrapping: a ceiling large enough to overflow the
/// multiplication is a ceiling the chain should refuse to register, and a
/// wrapped result would silently make it free.
#[must_use]
pub fn required_bond_atoms(ceiling_atoms: u128, ratio_num: u128, ratio_den: u128) -> u128 {
    if ratio_den == 0 {
        // A zero denominator is a configuration bug, not a division. Refuse
        // the largest possible requirement rather than produce a number that
        // looks plausible.
        return u128::MAX;
    }
    ceiling_atoms
        .saturating_mul(ratio_num)
        .saturating_add(ratio_den.saturating_sub(1))
        / ratio_den
}

/// What a prover is paid for carrying one attestation.
///
/// Two parts, because they answer different questions. The base fee pays for
/// the work of watching the chain, and is paid whether or not anybody uses the
/// attestation. The value fee pays for the risk, and scales with what the
/// attestation lets move - which is what makes lying unprofitable: the reward
/// for a false attestation is the same as for a true one, but the bond at risk
/// grows with the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverFee {
    pub base_atoms: u128,
    /// Basis points of the routed value. Ten thousand basis points is 100%.
    pub value_bps: u32,
}

impl ProverFee {
    /// The fee for one attestation carrying `value_atoms`.
    #[must_use]
    pub fn for_value(&self, value_atoms: u128) -> u128 {
        let value_part = value_atoms
            .saturating_mul(u128::from(self.value_bps))
            .saturating_add(BPS_DEN.saturating_sub(1))
            / BPS_DEN;
        self.base_atoms.saturating_add(value_part)
    }
}

/// Basis-point denominator, named so `value_bps: 25` cannot be misread as 25%.
pub const BPS_DEN: u128 = 10_000;

/// The reward a challenger earns for proving an attestation false.
///
/// It has to be large enough that watching for fraud is worth somebody's time,
/// and it comes out of the slashed bond rather than from nowhere - otherwise
/// challenging would be a cost the chain pays indefinitely and the incentive
/// to challenge would depend on the chain's budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeReward {
    /// Basis points of the slashed amount paid to the challenger.
    pub bps_of_slash: u32,
    /// A floor, so a small slashing still pays enough to be worth submitting.
    pub floor_atoms: u128,
}

impl ChallengeReward {
    /// What the challenger of a `slashed_atoms` slashing receives.
    #[must_use]
    pub fn for_slash(&self, slashed_atoms: u128) -> u128 {
        let part = slashed_atoms
            .saturating_mul(u128::from(self.bps_of_slash))
            / BPS_DEN;
        part.max(self.floor_atoms)
    }
}

/// The economics a domain registers with. All of it is public and all of it is
/// part of the domain's record, so a prover can decide whether the domain is
/// worth serving without asking anybody.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainEconomics {
    /// The most value this domain may route in one attestation. The bond
    /// requirement is derived from it.
    pub routing_ceiling_atoms: u128,
    pub fee: ProverFee,
    pub challenge: ChallengeReward,
    /// How many heights a prover has to wait before withdrawing a bond. A bond
    /// that can be pulled the moment a lie is detected is not a bond.
    pub unbonding_heights: u64,
}

impl DomainEconomics {
    /// The bond this domain currently requires.
    #[must_use]
    pub fn required_bond_atoms(&self) -> u128 {
        required_bond_atoms(self.routing_ceiling_atoms, BOND_RATIO_NUM, BOND_RATIO_DEN)
    }

    /// Whether a prover may serve this domain at all.
    #[must_use]
    pub fn admits(&self, bond: &ProverBond) -> bool {
        bond.is_sufficient(self.routing_ceiling_atoms)
    }

    /// The penalty for a contradicted attestation carrying `value_atoms`.
    ///
    /// Bounded by the bond: the penalty is what the prover has to lose, and a
    /// penalty larger than the bond is theatre.
    #[must_use]
    pub fn penalty_for(&self, value_atoms: u128, bond_atoms: u128) -> u128 {
        // The full routed value is the honest measure of the damage: a false
        // attestation that let ten thousand atoms move cost ten thousand
        // atoms. Capped at the bond because that is all there is.
        value_atoms.min(bond_atoms)
    }
}

/// Whether a prover's economics make honesty the cheaper option.
///
/// This is the check that decides whether the scheme works at all, written as
/// code rather than as prose so it can be tested with numbers instead of
/// argued about. It answers: is the profit from lying smaller than the loss?
///
/// A domain that fails this check is not refused - Budlum does not decide
/// whether a domain is good - but the answer is part of the profile, because a
/// reader is entitled to know that a domain's own numbers do not deter lying.
#[must_use]
pub fn honesty_is_cheaper(economics: &DomainEconomics, value_atoms: u128) -> bool {
    let gain = economics.fee.for_value(value_atoms);
    let loss = economics.penalty_for(value_atoms, economics.required_bond_atoms());
    gain < loss
}
