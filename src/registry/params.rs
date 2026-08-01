//! Tunable parameters for the permissionless registry.
//!
//! Per the instruction set these MUST NOT be hard-coded: minimum stake, the
//! Unbonding window and the per-offence slashing ratios are all governance /
//! Config parameters so they can change over the life of the chain without a
//! Code change. [`RegistryParams::default`] provides sane devnet defaults that
//! Are deliberately aligned with the existing consensus constants (see the
//! `Default` impl) so introducing the registry does not change current
//! Economic behaviour.

use crate::chain::fee_market::PPM_DENOMINATOR;
use crate::core::chain_config::FIXED_POINT_SCALE;
use serde::{Deserialize, Serialize};

/// Economic / timing parameters that gate participation and slashing.
///
/// `*_slash_ratio_fixed` values are `FIXED_POINT_SCALE`-scaled fractions in
/// `[0, FIXED_POINT_SCALE]` (e.g. `FIXED_POINT_SCALE / 2` == 50%).
///
/// # Adding a field is a state-format change
///
/// This struct is bincode-serialized into
/// `PermissionlessRegistry::root()`, which feeds the state root. bincode
/// encodes fields positionally with no names and no length prefix per struct,
/// so a snapshot written by an older binary has fewer fields than a newer
/// binary expects and fails to deserialize - `#[serde(default)]` on the
/// `params` field in `PermissionlessRegistry` only covers the field being
/// *absent*, not being *short*.
///
/// Two consequences, both intended here and both worth stating so the next
/// person adding a field knows what they are signing up for:
///
/// 1. Snapshots taken before the new field cannot be loaded afterwards.
/// 2. The state root changes, because `root()` hashes the serialized params.
///
/// That is acceptable pre-mainnet, where the chain is reset between releases.
/// After launch it is a migration, and the right shape is a versioned params
/// struct rather than an in-place field addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryParams {
    /// Minimum stake required to *newly* register for a role. This is an
    /// Economic floor, not a permission: any account meeting it may join.
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
    /// Participation before a liveness fault is raised (and slashed). Counted
    /// Consecutively and reset on any participation - never cumulative, so a
    /// Validator is not disproportionately punished for scattered misses.
    pub liveness_max_missed_epochs: u64,
    /// Fee required to submit a slashing report, as an anti-spam/DoS measure.
    /// Refunded to the reporter if the report turns out actionable (a correct
    /// Accusation must not be penalised); burned/kept otherwise. Set to 0 to
    /// Disable the fee entirely. Keeping the endpoint permissionless (anyone who
    /// Pays can submit) while making mass spam economically expensive and
    /// Sybil-resistant (each identity must also pay).
    pub slashing_report_fee: u64,
    /// Fee required to submit a ZK proof, as an anti-spam/DoS measure. Refunded
    /// If the proof verifies (an honest prover is never penalised); burned if it
    /// Fails verification. Set to 0 to disable. Same permissionless-but-costly
    /// Pattern as `slashing_report_fee`.
    pub proof_submission_fee: u64,
    /// Reward paid to a *registered* prover (PROVER role) for a proof that
    /// Verifies and advances domain state. Unregistered submitters still have
    /// Their valid proofs accepted but earn no reward. Set to 0 to disable
    /// Rewards.
    pub prover_reward: u64,
    /// Maximum number of cryptographically-invalid finality votes a validator
    /// May send within a single epoch before an `InvalidSignatureSpam` fault is
    /// Raised (and slashed). Counted per-epoch and reset each epoch.
    /// Set to 0 to disable invalid-vote-spam slashing entirely.
    ///
    /// Governance-settable: in `GOVERNANCE_PARAMETER_WHITELIST`, handled by
    /// Both `apply_registry_parameter_update` arms, and bounded by
    /// [`Self::validate`]. The `Default` impl called this
    /// "governance-tunable per network" for a while before any of that was
    /// True, which made a passed proposal fail at execution with "governance
    /// Parameter is not whitelisted".
    pub max_invalid_votes_per_epoch: u64,
    /// Whether the live epoch-close hook actually slashes validators for
    /// Liveness (downtime) faults.
    ///
    /// DEFAULT: `false` (observe-only). Turning liveness slashing on is a
    /// Deliberate, hard-to-reverse economic action: the underlying `slash`
    /// Jails a validator on ANY offence, so even a light (1%) liveness penalty
    /// Fully jails the offender. Per decision ("observe first,
    /// Validate on live/testnet, then activate"), this stays OFF until an
    /// Operator/governance explicitly enables it - the mechanism is fully wired
    /// And tested, but never auto-activates. Set to `true` to enable.
    pub liveness_slashing_enabled: bool,
    /// Relayer's cut of an inbound bridge transfer, in parts-per-million of the
    /// arriving amount.
    ///
    /// This is what lets someone bridge *into* Budlum without holding a single
    /// $BUD: the fee is taken from the asset arriving, never from a Budlum
    /// balance the user does not have yet.
    pub bridge_relayer_fee_ppm: u64,
    /// Floor on that cut, in base units of the arriving asset.
    ///
    /// A pure percentage rounds to zero on small transfers - at 1% every
    /// transfer under 100 units paid the relayer nothing, so an attacker could
    /// split a large bridge into 99-unit pieces and move it for free while
    /// relayers carried the external gas. The floor is what makes each relayed
    /// message cost something regardless of size.
    ///
    /// A transfer that cannot cover the floor is rejected rather than relayed
    /// at a loss.
    pub bridge_relayer_min_fee: u64,
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

    /// Protocol-level bounds for governance-tunable registry params.
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
        // A bridge fee at or above 100% would take the whole arriving amount
        // and credit the recipient nothing, which is indistinguishable from
        // theft by governance parameter.
        if self.bridge_relayer_fee_ppm >= PPM_DENOMINATOR {
            return Err("bridge_relayer_fee_ppm must be below 100%".into());
        }
        // Zero is a documented off-switch ("set to 0 to disable
        // invalid-vote-spam slashing entirely"), so the floor is not 1. The
        // ceiling is: a threshold above one epoch's worth of votes can never
        // be reached, which disables the fault while looking like it is
        // configured. `max_votes_per_msg` is 128 per network, so 100_000 is
        // orders of magnitude past any honest value and still refuses u64::MAX.
        if self.max_invalid_votes_per_epoch > 100_000 {
            return Err("max_invalid_votes_per_epoch must be at most 100,000".into());
        }
        Ok(())
    }
}

impl Default for RegistryParams {
    fn default() -> Self {
        RegistryParams {
            // Aligned with `PoSConfig::min_stake` and `ConsensusParams.min_stake`
            // (1000) so the registry and the validator set share one stake
            // Floor and never disagree.
            min_stake: 1_000,
            // Aligned with `core::account::UNBONDING_EPOCHS` (7) to preserve the
            // Existing unbonding behaviour. NOTE: the wall-clock length of the
            // Window depends on the network's slot/epoch length; operators
            // Targeting a multi-day window on mainnet should raise this via
            // Governance rather than editing code.
            unbonding_epochs: crate::core::account::UNBONDING_EPOCHS,
            // 50% - matches `PoSConfig::double_sign_penalty`.
            double_sign_slash_ratio_fixed: FIXED_POINT_SCALE / 2,
            // 1% - downtime is a light offence.
            liveness_slash_ratio_fixed: FIXED_POINT_SCALE / 100,
            // 100% - proven malice burns the whole bond.
            malicious_slash_ratio_fixed: FIXED_POINT_SCALE,
            // 20 consecutive missed epochs. Aligned with mainnet readiness decision
            // For operator tolerance and reliability.
            liveness_max_missed_epochs: 20,
            // 1% of the default min_stake (1000) = 10. Small enough not to deter
            // An honest reporter (it is refunded when the report is actionable),
            // Large enough that flooding thousands of junk reports is costly.
            // Scaled to min_stake so it tracks the chain's economic unit.
            slashing_report_fee: 10,
            // 1% of min_stake = 10, mirroring slashing_report_fee: refunded on a
            // Valid proof so honest provers pay nothing net, but flooding invalid
            // Proofs is costly and sybil-resistant.
            proof_submission_fee: 10,
            // Fixed-supply policy: proof rewards cannot mint. A future
            // Transaction-scoped fee pool may fund this, but until that pool is
            // Committed in state the only safe reward is zero.
            prover_reward: 0,
            // OFF by default. Real liveness slashing (which also jails,
            // Via slash) must be explicitly enabled after live/testnet
            // Validation of the observe-mode signal.
            // 20 invalid votes in a single epoch. Generous enough that a brief
            // Software bug / desync producing a handful of malformed votes is
            // Tolerated, low enough that sustained garbage-signature spam is
            // Caught within one epoch. Governance-tunable per network.
            max_invalid_votes_per_epoch: 20,
            liveness_slashing_enabled: true,
            // 1% - the rate the three hardcoded call sites already used, now
            // stated once and tunable.
            bridge_relayer_fee_ppm: 10_000,
            // Matches `slashing_report_fee` / `proof_submission_fee` (1% of the
            // default min_stake). Small enough not to matter for a real
            // transfer, large enough that splitting a bridge into dust costs
            // more than doing it in one message.
            bridge_relayer_min_fee: 10,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The struct is hashed into the state root, so its serialized shape is
    /// consensus. This pins the field count: adding one is a deliberate
    /// state-format change, not a refactor.
    ///
    /// If this fails, the change is not necessarily wrong - but it is not
    /// backwards compatible, and the `# Adding a field` note above applies.
    #[test]
    fn registry_params_serialized_shape_is_pinned() {
        let encoded =
            bincode::serialize(&RegistryParams::default()).expect("RegistryParams is serializable");
        // 12 u64 fields + 1 bool. bincode writes u64 as 8 bytes, bool as 1.
        assert_eq!(
            encoded.len(),
            12 * 8 + 1,
            "RegistryParams changed shape: old snapshots can no longer be \
             deserialized and the state root moves. See the type's docs."
        );
    }

    /// A field the docs call governance-settable must actually be votable.
    ///
    /// `max_invalid_votes_per_epoch` carried "Governance-tunable per network"
    /// While being absent from `GOVERNANCE_PARAMETER_WHITELIST`. A proposal
    /// Naming it fails in `validate_governance_parameter_update` with
    /// "governance parameter is not whitelisted" - after the vote, after the
    /// Timelock. The comment described an intention, not the code.
    ///
    /// `bridge_relayer_fee_ppm` had the mirror-image gap once: whitelisted but
    /// Missing from `apply_registry_parameter_update`, so the vote passed and
    /// Then did nothing.
    ///
    /// This reads the doc comment attached to each field rather than a
    /// Hand-maintained list, so a new field that claims to be
    /// Governance-settable and is not wired up fails here instead of at
    /// Execution time on a live chain.
    ///
    /// Only the unbroken run of `///` lines directly above the field counts.
    /// A wider window bleeds into the neighbouring field's documentation and
    /// Reports three false positives.
    #[test]
    fn every_field_documented_as_governance_settable_is_whitelisted() {
        use crate::core::governance::GOVERNANCE_PARAMETER_WHITELIST;

        let src = include_str!("params.rs");
        let lines: Vec<&str> = src.lines().collect();
        let mut checked = 0;

        for (i, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("pub ") else {
                continue;
            };
            let Some((name, _)) = rest.split_once(':') else {
                continue;
            };
            if !name.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                continue;
            }

            let mut doc = String::new();
            for above in lines[..i].iter().rev() {
                let above = above.trim();
                if !above.starts_with("///") {
                    break;
                }
                doc.push_str(&above.to_lowercase());
                doc.push(' ');
            }

            if doc.contains("governance-tunable") || doc.contains("governance-settable") {
                checked += 1;
                assert!(
                    GOVERNANCE_PARAMETER_WHITELIST.contains(&name),
                    "{name} is documented as governance-settable but is not in \
                     GOVERNANCE_PARAMETER_WHITELIST - a proposal naming it is \
                     refused after the vote"
                );
            }
        }

        assert!(
            checked > 0,
            "no field claims to be governance-settable - the doc scan is broken, \
             not the code"
        );
    }

    /// Governance must not be able to set a threshold that can never be hit.
    ///
    /// Zero is a documented off-switch, so the floor stays open. The ceiling
    /// Is the real risk: a value above any reachable vote count disables the
    /// Invalid-signature-spam fault while looking configured.
    #[test]
    fn max_invalid_votes_per_epoch_is_bounded() {
        let p = RegistryParams {
            max_invalid_votes_per_epoch: 0,
            ..Default::default()
        };
        assert!(p.validate().is_ok(), "0 is the documented off-switch");

        let p = RegistryParams {
            max_invalid_votes_per_epoch: 100_000,
            ..Default::default()
        };
        assert!(p.validate().is_ok(), "the ceiling itself is allowed");

        let p = RegistryParams {
            max_invalid_votes_per_epoch: 100_001,
            ..Default::default()
        };
        let err = p.validate().expect_err("above the ceiling must be refused");
        assert!(err.contains("max_invalid_votes_per_epoch"), "got: {err}");

        let p = RegistryParams {
            max_invalid_votes_per_epoch: u64::MAX,
            ..Default::default()
        };
        assert!(
            p.validate().is_err(),
            "u64::MAX disables the fault while looking configured"
        );
    }

    #[test]
    fn registry_params_validate_accepts_defaults() {
        assert!(RegistryParams::default().validate().is_ok());
    }

    /// A bridge fee of 100% or more would credit the recipient nothing.
    #[test]
    fn bridge_fee_at_or_above_one_hundred_percent_is_refused() {
        let mut p = RegistryParams {
            bridge_relayer_fee_ppm: PPM_DENOMINATOR,
            ..Default::default()
        };
        assert!(p.validate().is_err(), "100% bridge fee must be refused");
        p.bridge_relayer_fee_ppm = PPM_DENOMINATOR + 1;
        assert!(p.validate().is_err(), "above 100% must be refused");
        p.bridge_relayer_fee_ppm = PPM_DENOMINATOR - 1;
        assert!(
            p.validate().is_ok(),
            "just under 100% is a policy choice, not an error"
        );
    }

    /// The default rate is the one the hardcoded call sites used, so this
    /// change is not a silent repricing of the bridge.
    #[test]
    fn default_bridge_fee_matches_the_rate_it_replaced() {
        let p = RegistryParams::default();
        assert_eq!(p.bridge_relayer_fee_ppm, 10_000, "10_000 ppm == 1%");
        // 1% of 1_000_000 base units, the old `amount * 1 / 100`.
        assert_eq!(
            u128::from(p.bridge_relayer_fee_ppm) * 1_000_000 / u128::from(PPM_DENOMINATOR),
            10_000
        );
    }

    #[test]
    fn registry_params_validate_rejects_zero_unbonding() {
        let p = RegistryParams {
            unbonding_epochs: 0,
            ..Default::default()
        };
        let err = p.validate().expect_err("zero unbonding must fail");
        assert!(err.contains("unbonding_epochs"), "got: {err}");
    }

    #[test]
    fn registry_params_validate_rejects_slash_above_scale() {
        let p = RegistryParams {
            double_sign_slash_ratio_fixed: FIXED_POINT_SCALE + 1,
            ..Default::default()
        };
        let err = p.validate().expect_err("slash > scale must fail");
        assert!(err.contains("double_sign_slash_ratio_fixed"), "got: {err}");
    }
}
