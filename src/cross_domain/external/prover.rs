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
        self.bond_atoms
            >= required_bond_atoms(current_ceiling_atoms, BOND_RATIO_NUM, BOND_RATIO_DEN)
    }

    /// The live bond: what is actually there to lose.
    #[must_use]
    pub const fn live_atoms(&self) -> u128 {
        self.bond_atoms
    }

    /// Applies a slashing. Returns the amount actually taken, which may be
    /// less than requested if the bond is smaller than the penalty - a prover
    /// cannot lose more than they posted, and pretending otherwise would make
    /// the accounting lie.
    pub fn slash(
        &mut self,
        at_height: u64,
        evidence_digest: [u8; 32],
        want_atoms: u128,
        challenger: Address,
        challenge_reward_atoms: u128,
    ) -> u128 {
        let taken = self.bond_atoms.min(want_atoms);
        self.bond_atoms = self.bond_atoms.saturating_sub(taken);
        self.slashed_atoms = self.slashed_atoms.saturating_add(taken);
        self.slashings.push(Slashing {
            at_height,
            evidence_digest,
            amount_atoms: taken,
            challenger,
            // The reward comes out of the slashed bond,
            // so it cannot exceed what was taken - a floor that outran the
            // slash would pay the challenger from nowhere.
            challenge_reward_atoms: challenge_reward_atoms.min(taken),
        });
        taken
    }
}

/// The bond ratio, as a pair.
///
/// The denominator is a power of ten so the
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
        .checked_mul(ratio_num)
        .map_or(u128::MAX, |prod| {
            let q = prod / ratio_den;
            let rem = prod % ratio_den;
            // Preserve the legacy `u128::MAX` 1/10 edge while avoiding `prod + (den - 1)` truncation.
            if prod == u128::MAX && ratio_num == 1 {
                q
            } else {
                q.saturating_add(u128::from(rem != 0))
            }
        })
}

/// What a prover is paid for carrying one attestation.
///
/// Two parts, because they answer different questions. The base fee pays for
/// the work of watching the chain, and is paid whether or not anybody uses the
/// attestation. The value fee pays for the risk, and scales with what the
/// attestation lets move - which is what makes lying unprofitable: the reward
/// for a false attestation is the same as for a true one, but the bond at risk
/// grows with the value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProverFee {
    pub base_atoms: u128,
    /// Basis points of the routed value. Ten thousand basis points is 100%.
    pub value_bps: u32,
}

impl ProverFee {
    /// The fee for one attestation carrying `value_atoms`.
    #[must_use]
    pub fn for_value(&self, value_atoms: u128) -> u128 {
        if self.value_bps == 0 || value_atoms == 0 {
            return self.base_atoms;
        }
        let bps = u128::from(self.value_bps);
        let q = value_atoms / BPS_DEN;
        let r = value_atoms % BPS_DEN;
        let scaled_r = r.saturating_mul(bps);
        let rem_ceil = (scaled_r / BPS_DEN).saturating_add(u128::from(scaled_r % BPS_DEN != 0));
        let value_part = q.saturating_mul(bps).saturating_add(rem_ceil);
        self.base_atoms.saturating_add(value_part)
    }

    /// Escalates the base + value attestation fee when a domain has been
    /// neglected beyond `IDLE_ESCALATION_GRACE_HEIGHTS` heights without a
    /// fresh attestation. Uses pure saturating `u128` integer arithmetic and
    /// caps the multiplier at `IDLE_ESCALATION_MAX_BPS` (`5x`).
    #[must_use]
    fn for_value_with_idle_escalation(&self, value_atoms: u128, idle_heights: u64) -> u128 {
        let base_fee = self.for_value(value_atoms);
        if idle_heights <= IDLE_ESCALATION_GRACE_HEIGHTS || base_fee == 0 {
            return base_fee;
        }
        let excess = idle_heights.saturating_sub(IDLE_ESCALATION_GRACE_HEIGHTS);
        let steps = u128::from(excess / IDLE_ESCALATION_STEP_HEIGHTS);
        if steps == 0 {
            return base_fee;
        }
        let bonus_bps = steps.saturating_mul(u128::from(IDLE_ESCALATION_STEP_BPS));
        let mult_bps = BPS_DEN
            .saturating_add(bonus_bps)
            .min(u128::from(IDLE_ESCALATION_MAX_BPS));
        let q = base_fee / BPS_DEN;
        let r = base_fee % BPS_DEN;
        let scaled_r = r.saturating_mul(mult_bps);
        let rem_ceil = (scaled_r / BPS_DEN).saturating_add(u128::from(scaled_r % BPS_DEN != 0));
        q.saturating_mul(mult_bps).saturating_add(rem_ceil)
    }
}

/// Heights a domain may stay idle before carrier reward escalation begins.
const IDLE_ESCALATION_GRACE_HEIGHTS: u64 = 100;
/// Idle height step between successive carrier reward increases.
const IDLE_ESCALATION_STEP_HEIGHTS: u64 = 100;
/// Reward increase per idle step in basis points (`2_500` = +25%).
const IDLE_ESCALATION_STEP_BPS: u32 = 2_500;
/// Hard ceiling on idle escalation multiplier in basis points (`50_000` = 5x).
const IDLE_ESCALATION_MAX_BPS: u32 = 50_000;

/// Basis-point denominator, named so `value_bps: 25` cannot be misread as 25%.
pub const BPS_DEN: u128 = 10_000;

/// The reward a challenger earns for proving an attestation false.
///
/// It has to be large enough that watching for fraud is worth somebody's time,
/// and it comes out of the slashed bond rather than from nowhere - otherwise
/// challenging would be a cost the chain pays indefinitely and the incentive
/// to challenge would depend on the chain's budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeReward {
    /// Basis points of the slashed amount paid to the challenger.
    pub bps_of_slash: u32,
    /// A floor, so a small slashing still pays enough to be worth submitting.
    pub floor_atoms: u128,
}

impl ChallengeReward {
    /// What the challenger of a `slashed_atoms` slashing receives.
    ///
    /// A zero slash pays zero (never an unbacked floor), and `bps_of_slash` is
    /// capped at `10_000` (100% of the slash) without intermediate `u128` overflow.
    #[must_use]
    pub fn for_slash(&self, slashed_atoms: u128) -> u128 {
        if slashed_atoms == 0 {
            return 0;
        }
        let capped_bps = u128::from(self.bps_of_slash).min(BPS_DEN);
        let q = slashed_atoms / BPS_DEN;
        let r = slashed_atoms % BPS_DEN;
        let part = q
            .saturating_mul(capped_bps)
            .saturating_add((r * capped_bps) / BPS_DEN);
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

    /// What a lying prover actually loses on a contradicted attestation
    /// carrying `value_atoms`: the penalty, net of the challenger's share.
    ///
    /// The challenger's share is paid to whoever presents the contradiction,
    /// and nothing binds that address to a stranger - a prover with two
    /// addresses presents its own and takes the share back. So the gross
    /// penalty overstates the deterrent by exactly that share, and a domain
    /// paying the whole slash to the challenger deters nothing. A share
    /// larger than the penalty (a floor above the bond) leaves zero, never a
    /// negative loss: the slash pays out no more than it took.
    #[must_use]
    fn net_loss_for(&self, value_atoms: u128) -> u128 {
        let penalty = self.penalty_for(value_atoms, self.required_bond_atoms());
        penalty.saturating_sub(self.challenge.for_slash(penalty))
    }

    /// Carrier reward for serving an attestation carrying `value_atoms` after
    /// `idle_heights` heights of inactivity. Escalates monotonically while a
    /// domain goes unserved, yet stays strictly below the prover's net
    /// slashing loss whenever that loss is positive, so idle escalation never
    /// makes lying profitable - not even for a prover that challenges itself.
    #[must_use]
    pub fn carrier_reward_for_idle(&self, value_atoms: u128, idle_heights: u64) -> u128 {
        let escalated = self
            .fee
            .for_value_with_idle_escalation(value_atoms, idle_heights);
        let loss = self.net_loss_for(value_atoms);
        if loss > 0 {
            escalated.min(loss.saturating_sub(1))
        } else {
            escalated
        }
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
    // The loss a liar can count on is the penalty net of the challenger's
    // share it can route back to itself (`DomainEconomics::net_loss_for`);
    // measured against the gross penalty, a 100% challenger share read as a
    // deterrent while leaving none.
    let loss = economics.net_loss_for(value_atoms);
    gain < loss
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_domain_escalates_carrier_reward_until_cap_and_preserves_honesty_rule() {
        let econ = DomainEconomics {
            routing_ceiling_atoms: 1_000_000,
            fee: ProverFee {
                base_atoms: 1_000,
                value_bps: 10, // 0.10% -> 1_000 value fee, 2_000 total at ceiling
            },
            challenge: ChallengeReward {
                bps_of_slash: 2_500,
                floor_atoms: 500,
            },
            unbonding_heights: 100,
        };
        let ceiling = econ.routing_ceiling_atoms;
        let loss = econ.penalty_for(ceiling, econ.required_bond_atoms());
        assert_eq!(loss, 100_000);

        let r0 = econ.carrier_reward_for_idle(ceiling, 0);
        let r_grace = econ.carrier_reward_for_idle(ceiling, IDLE_ESCALATION_GRACE_HEIGHTS);
        let r_step1 = econ.carrier_reward_for_idle(ceiling, 200);
        let r_step2 = econ.carrier_reward_for_idle(ceiling, 300);
        let r_cap = econ.carrier_reward_for_idle(ceiling, 10_000);
        let r_huge = econ.carrier_reward_for_idle(ceiling, u64::MAX);

        assert_eq!(r0, 2_000);
        assert_eq!(r_grace, r0);
        assert!(r_step1 > r_grace, "reward must rise after grace window");
        assert!(r_step2 > r_step1, "reward must keep rising while idle");
        assert_eq!(r_cap, 10_000, "5x escalation cap on 2_000 base fee");
        assert_eq!(r_huge, r_cap, "saturation at cap prevents overflow");
        assert!(
            r_huge < loss,
            "idle escalation must never make lying profitable"
        );

        // Tight-margin domain: escalation is clamped strictly below slashing loss.
        let tight = DomainEconomics {
            routing_ceiling_atoms: 10_000, // required bond = 1_000 = loss
            fee: ProverFee {
                base_atoms: 400,
                value_bps: 0,
            },
            challenge: ChallengeReward::default(),
            unbonding_heights: 10,
        };
        let tight_loss = tight.penalty_for(10_000, tight.required_bond_atoms());
        let tight_reward = tight.carrier_reward_for_idle(10_000, 10_000);
        assert_eq!(tight_loss, 1_000);
        assert_eq!(tight_reward, 999);
        assert!(tight_reward < tight_loss);
    }

    /// The challenger's share of a slash is paid to whoever presents the
    /// contradiction, and nothing stops a lying prover from presenting it
    /// from a second address. The loss that deters lying is therefore the
    /// penalty net of the largest rebate the prover can route back to
    /// itself, not the gross penalty.
    #[test]
    fn the_deterrent_is_the_penalty_net_of_the_challenger_rebate() {
        let econ = DomainEconomics {
            routing_ceiling_atoms: 1_000_000,
            fee: ProverFee {
                base_atoms: 1_000,
                value_bps: 10,
            },
            challenge: ChallengeReward {
                bps_of_slash: 2_500,
                floor_atoms: 500,
            },
            unbonding_heights: 100,
        };
        let ceiling = econ.routing_ceiling_atoms;
        // Gross penalty 100_000 (the bond), rebate 25_000, net 75_000.
        assert_eq!(
            econ.penalty_for(ceiling, econ.required_bond_atoms()),
            100_000
        );
        assert_eq!(econ.net_loss_for(ceiling), 75_000);
        // A floor above the penalty cannot turn the rebate into a profit: the
        // rebate is capped at what the slash took, so the net loss is zero,
        // never negative.
        let floor_heavy = DomainEconomics {
            challenge: ChallengeReward {
                bps_of_slash: 0,
                floor_atoms: u128::MAX,
            },
            ..econ
        };
        assert_eq!(floor_heavy.net_loss_for(ceiling), 0);
    }

    /// A domain that pays the challenger the whole slash makes a false
    /// attestation free for a prover with two addresses: the fee is earned,
    /// the penalty comes back as the challenger's reward. Such economics do
    /// not make honesty cheaper and must read as dishonest.
    #[test]
    fn a_full_challenger_rebate_makes_lying_free_and_is_not_honest() {
        let econ = DomainEconomics {
            routing_ceiling_atoms: 1_000_000,
            fee: ProverFee {
                base_atoms: 1_000,
                value_bps: 10,
            },
            challenge: ChallengeReward {
                bps_of_slash: 10_000,
                floor_atoms: 0,
            },
            unbonding_heights: 100,
        };
        let ceiling = econ.routing_ceiling_atoms;
        assert_eq!(econ.net_loss_for(ceiling), 0);
        assert!(
            !honesty_is_cheaper(&econ, ceiling),
            "a 100% challenger rebate leaves no deterrent"
        );
        // The same fee under a 25% rebate still loses 75_000 against a 2_000
        // gain, so the rule refuses exactly the economics that leak.
        let quarter = DomainEconomics {
            challenge: ChallengeReward {
                bps_of_slash: 2_500,
                floor_atoms: 0,
            },
            ..econ
        };
        assert!(honesty_is_cheaper(&quarter, ceiling));
        // And a rebate that leaves less than the fee behind is dishonest even
        // though the gross penalty dwarfs the fee: 99.9% rebate -> net 100 < 2_000.
        let leaky = DomainEconomics {
            challenge: ChallengeReward {
                bps_of_slash: 9_990,
                floor_atoms: 0,
            },
            ..econ
        };
        assert_eq!(
            leaky.penalty_for(ceiling, leaky.required_bond_atoms()),
            100_000
        );
        assert!(!honesty_is_cheaper(&leaky, ceiling));
    }

    /// Idle escalation is capped below what lying costs; that cost is the net
    /// loss, so a generous rebate tightens the cap rather than loosening it.
    #[test]
    fn idle_escalation_stays_below_the_net_loss_not_the_gross_penalty() {
        let econ = DomainEconomics {
            routing_ceiling_atoms: 10_000, // bond 1_000 = gross penalty
            fee: ProverFee {
                base_atoms: 400,
                value_bps: 0,
            },
            challenge: ChallengeReward {
                bps_of_slash: 8_000, // rebate 800 -> net loss 200
                floor_atoms: 0,
            },
            unbonding_heights: 10,
        };
        assert_eq!(econ.net_loss_for(10_000), 200);
        let escalated = econ.carrier_reward_for_idle(10_000, 10_000);
        assert!(
            escalated < 200,
            "idle escalation {escalated} must stay below the net loss 200"
        );
    }
}
