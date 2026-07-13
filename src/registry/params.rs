//! Tunable parameters for the permissionless registry.
//!
//! Per the instruction set these MUST NOT be hard-coded: minimum stake, the
//! unbonding window and the per-offence slashing ratios are all governance /
//! config parameters so they can change over the life of the chain without a
//! code change. [`RegistryParams::default`] provides sane devnet defaults that
//! are deliberately aligned with the existing consensus constants (see the
//! `Default` impl) so introducing the registry does not change current
//! economic behaviour.

use crate::core::chain_config::FIXED_POINT_SCALE;
use serde::{Deserialize, Serialize};

/// Economic / timing parameters that gate participation and slashing.
///
/// `*_slash_ratio_fixed` values are `FIXED_POINT_SCALE`-scaled fractions in
/// `[0, FIXED_POINT_SCALE]` (e.g. `FIXED_POINT_SCALE / 2` == 50%).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryParams {
    /// Minimum stake required to *newly* register for a role. This is an
    /// economic floor, not a permission: any account meeting it may join.
    pub min_stake: u64,
    /// Number of epochs unbonded stake stays locked before withdrawal.
    pub unbonding_epochs: u64,
    /// Penalty ratio for equivocation / double-sign (severe).
    pub double_sign_slash_ratio_fixed: u64,
    /// Penalty ratio for liveness / downtime faults (light).
    pub liveness_slash_ratio_fixed: u64,
    /// Penalty ratio for provable malicious behaviour (maximal).
    pub malicious_slash_ratio_fixed: u64,
    /// Number of *consecutive* epochs a validator may miss expected consensus
    /// participation before a liveness fault is raised (and slashed). Counted
    /// consecutively and reset on any participation — never cumulative, so a
    /// validator is not disproportionately punished for scattered misses.
    pub liveness_max_missed_epochs: u64,
    /// Fee required to submit a slashing report, as an anti-spam/DoS measure.
    /// Refunded to the reporter if the report turns out actionable (a correct
    /// accusation must not be penalised); burned/kept otherwise. Set to 0 to
    /// disable the fee entirely. Keeping the endpoint permissionless (anyone who
    /// pays can submit) while making mass spam economically expensive and
    /// sybil-resistant (each identity must also pay).
    pub slashing_report_fee: u64,
    /// Fee required to submit a ZK proof, as an anti-spam/DoS measure. Refunded
    /// if the proof verifies (an honest prover is never penalised); burned if it
    /// fails verification. Set to 0 to disable. Same permissionless-but-costly
    /// pattern as `slashing_report_fee`.
    pub proof_submission_fee: u64,
    /// Reward paid to a *registered* prover (PROVER role) for a proof that
    /// verifies and advances domain state. Unregistered submitters still have
    /// their valid proofs accepted but earn no reward. Set to 0 to disable
    /// rewards.
    pub prover_reward: u64,
    /// Maximum number of cryptographically-invalid finality votes a validator
    /// may send within a single epoch before an `InvalidSignatureSpam` fault is
    /// raised (and slashed). Counted per-epoch and reset each epoch (Tur 15).
    /// Set to 0 to disable invalid-vote-spam slashing entirely.
    pub max_invalid_votes_per_epoch: u64,
    /// Whether the live epoch-close hook actually slashes validators for
    /// liveness (downtime) faults (Tur 12).
    ///
    /// DEFAULT: `false` (observe-only). Turning liveness slashing on is a
    /// deliberate, hard-to-reverse economic action: the underlying `slash()`
    /// jails a validator on ANY offence, so even a light (1%) liveness penalty
    /// fully jails the offender. Per the Tur-10 decision ("observe first,
    /// validate on live/testnet, then activate"), this stays OFF until an
    /// operator/governance explicitly enables it — the mechanism is fully wired
    /// and tested, but never auto-activates. Set to `true` to enable.
    pub liveness_slashing_enabled: bool,
}

impl RegistryParams {
    /// Resolve the slash ratio for a given condition.
    pub fn slash_ratio(&self, condition: super::permissionless::SlashingCondition) -> u64 {
        use super::permissionless::SlashingCondition::*;
        match condition {
            DoubleSign => self.double_sign_slash_ratio_fixed,
            LivenessFault => self.liveness_slash_ratio_fixed,
            MaliciousBehaviour => self.malicious_slash_ratio_fixed,
        }
    }

    /// Tur 11: protocol-level bounds for governance-tunable registry params.
    /// Prevents extreme values (e.g. zero unbonding, >100% slash ratios).
    pub fn validate(&self) -> Result<(), String> {
        if self.min_stake < 100 {
            return Err("min_stake must be at least 100".into());
        }
        if self.unbonding_epochs == 0 || self.unbonding_epochs > 100_000 {
            return Err("unbonding_epochs must be between 1 and 100,000".into());
        }
        if self.double_sign_slash_ratio_fixed > FIXED_POINT_SCALE {
            return Err("double_sign_slash_ratio_fixed cannot exceed FIXED_POINT_SCALE".into());
        }
        if self.liveness_slash_ratio_fixed > FIXED_POINT_SCALE {
            return Err("liveness_slash_ratio_fixed cannot exceed FIXED_POINT_SCALE".into());
        }
        if self.malicious_slash_ratio_fixed > FIXED_POINT_SCALE {
            return Err("malicious_slash_ratio_fixed cannot exceed FIXED_POINT_SCALE".into());
        }
        Ok(())
    }
}

impl Default for RegistryParams {
    fn default() -> Self {
        RegistryParams {
            // Aligned with `PoSConfig::min_stake` and `ConsensusParams.min_stake`
            // (1000) so the registry and the validator set share one stake
            // floor and never disagree.
            min_stake: 1_000,
            // Aligned with `core::account::UNBONDING_EPOCHS` (7) to preserve the
            // existing unbonding behaviour. NOTE: the wall-clock length of the
            // window depends on the network's slot/epoch length; operators
            // targeting a multi-day window on mainnet should raise this via
            // governance rather than editing code.
            unbonding_epochs: crate::core::account::UNBONDING_EPOCHS,
            // 50% — matches `PoSConfig::double_sign_penalty`.
            double_sign_slash_ratio_fixed: FIXED_POINT_SCALE / 2,
            // 1% — downtime is a light offence.
            liveness_slash_ratio_fixed: FIXED_POINT_SCALE / 100,
            // 100% — proven malice burns the whole bond.
            malicious_slash_ratio_fixed: FIXED_POINT_SCALE,
            // 10 consecutive missed epochs. Long enough to tolerate transient
            // network blips / node restarts, short enough to evict a truly dead
            // validator promptly. Governance-tunable per network (a longer
            // slot/epoch means a longer wall-clock tolerance).
            liveness_max_missed_epochs: 10,
            // 1% of the default min_stake (1000) = 10. Small enough not to deter
            // an honest reporter (it is refunded when the report is actionable),
            // large enough that flooding thousands of junk reports is costly.
            // Scaled to min_stake so it tracks the chain's economic unit.
            slashing_report_fee: 10,
            // 1% of min_stake = 10, mirroring slashing_report_fee: refunded on a
            // valid proof so honest provers pay nothing net, but flooding invalid
            // proofs is costly and sybil-resistant.
            proof_submission_fee: 10,
            // 5x the submission fee (50) as a modest positive incentive for
            // registered provers to do useful proving work. Kept small for
            // devnet; production reward economics are out of scope this turn.
            prover_reward: 50,
            // Tur 12: OFF by default. Real liveness slashing (which also jails,
            // via slash()) must be explicitly enabled after live/testnet
            // validation of the observe-mode signal (Tur 10/11).
            // 20 invalid votes in a single epoch. Generous enough that a brief
            // software bug / desync producing a handful of malformed votes is
            // tolerated, low enough that sustained garbage-signature spam is
            // caught within one epoch. Governance-tunable per network.
            max_invalid_votes_per_epoch: 20,
            liveness_slashing_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tur11_registry_params_validate_accepts_defaults() {
        assert!(RegistryParams::default().validate().is_ok());
    }

    #[test]
    fn tur11_registry_params_validate_rejects_zero_unbonding() {
        let mut p = RegistryParams::default();
        p.unbonding_epochs = 0;
        let err = p.validate().expect_err("zero unbonding must fail");
        assert!(err.contains("unbonding_epochs"), "got: {err}");
    }

    #[test]
    fn tur11_registry_params_validate_rejects_slash_above_scale() {
        let mut p = RegistryParams::default();
        p.double_sign_slash_ratio_fixed = FIXED_POINT_SCALE + 1;
        let err = p.validate().expect_err("slash > scale must fail");
        assert!(err.contains("double_sign_slash_ratio_fixed"), "got: {err}");
    }
}
