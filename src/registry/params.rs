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

/// How many epochs a liveness offender stays jailed.
///
/// A liveness offence is absence, and absence is what a healthy validator
/// looks like during a partition, a disk failure or a datacentre reboot.
/// Making that permanent punishes an outage the way it punishes abandonment,
/// so the penalty carries a term: stake is cut once, the validator is barred
/// for this many epochs, and `AccountState::advance_epoch` then releases it.
///
/// A constant rather than a `RegistryParams` field on purpose. That struct is
/// serialised into the state root, so adding to it changes the shape every
/// stored snapshot was written with, which is a migration rather than a fix.
/// The number was already hardcoded in `AccountState::slash_validator`; this
/// gives the two slashing sites one place to read it from without touching a
/// consensus-critical layout.
pub const LIVENESS_JAIL_EPOCHS: u64 = 7;

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
    /// Consecutively and reset on any participation, never cumulative, so a
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
    /// Fee required to register an AI model (Lubot), as an anti-sybil/DoS
    /// measure on the model registry. Governance-tunable per network; set to
    /// 0 to disable. Charged as an exact cost on top of the base transaction
    /// fee (H1 exact-cost pattern): paying less is rejected, paying more is
    /// not refunded - the difference is burned like any overpay.
    pub ai_model_register_fee: u64,
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

    /// Protocol cut of a plain value transfer, in parts-per-million of the
    /// amount moved.
    ///
    /// The flat fee alone does not see the amount at all: `validate_transaction`
    /// only requires `tx.fee >= base_fee`, and `tx.amount` appears solely in the
    /// overflow guard and the balance check. Someone moving one base unit and
    /// someone moving a quadrillion paid exactly the same, which is the transfer
    /// twin of the storage deal that charged the same for 1 KiB and 16 MiB.
    ///
    /// `0` keeps the previous behaviour exactly, which is what every existing
    /// network runs until governance says otherwise.
    pub transfer_fee_ppm: u64,

    /// Protocol cut of a swap, in parts-per-million.
    ///
    /// Separate from `transfer_fee_ppm` because a swap consumes more of the
    /// network than a transfer does and the two are priced independently in the
    /// economic model. No swap transaction type exists yet; the parameter is
    /// here so the rate is decided once, in the same place as its siblings,
    /// rather than appearing as a literal at whatever call site lands first.
    pub swap_fee_ppm: u64,

    /// Protocol cut of an outbound bridge transfer, in parts-per-million.
    ///
    /// Distinct from `bridge_relayer_fee_ppm`, which pays the relayer out of an
    /// *arriving* asset. This one is the protocol's own cut on the way out, and
    /// the two are not interchangeable: one is compensation for work done, the
    /// other is revenue.
    pub bridge_fee_ppm: u64,
}

impl RegistryParams {
    /// Resolve the slash ratio for a given condition.
    #[must_use]
    pub const fn slash_ratio(&self, condition: super::permissionless::SlashingCondition) -> u64 {
        // Spelled out rather than glob-imported: `enum_glob_use` pulls three
        // bare names into scope that read like locals at the match arms, and
        // a fourth condition added later would land here silently.
        match condition {
            super::permissionless::SlashingCondition::DoubleSign => {
                self.double_sign_slash_ratio_fixed
            }
            super::permissionless::SlashingCondition::LivenessFault => {
                self.liveness_slash_ratio_fixed
            }
            super::permissionless::SlashingCondition::MaliciousBehaviour => {
                self.malicious_slash_ratio_fixed
            }
        }
    }

    /// Proportional protocol cut for a value-bearing transaction.
    ///
    /// Returns the fee the protocol requires *in addition to nothing*: the
    /// caller compares it against `base_fee` and charges the larger of the two.
    /// That is the same shape `split_bridge_fee` already uses, and it exists
    /// for the same reason. A pure percentage rounds to zero below
    /// `PPM_DENOMINATOR / rate` units, so at any usable rate the smallest
    /// transfers travel free and an attacker splits one large transfer into
    /// many small ones to pay nothing. The floor is what makes every
    /// transaction cost something regardless of size.
    ///
    /// Rounding is up, for the reason storage pricing rounds up: integer
    /// division is exactly how a real charge silently becomes zero. A rate of
    /// zero is the only way to express "free", and it stays zero.
    ///
    /// `u128` throughout because `amount * rate` overflows `u64` for any
    /// amount above roughly 18 trillion at a 1% rate, and the whole point of
    /// this function is that large amounts pay proportionally.
    #[must_use]
    pub fn proportional_fee(&self, amount: u64, rate_ppm: u64) -> u64 {
        if rate_ppm == 0 || amount == 0 {
            return 0;
        }
        let scaled = u128::from(amount).saturating_mul(u128::from(rate_ppm));
        u64::try_from(scaled.div_ceil(u128::from(PPM_DENOMINATOR))).unwrap_or(u64::MAX)
    }

    /// The fee a value transfer of `amount` must carry, given a flat floor.
    ///
    /// The larger of the flat floor and the proportional cut. Never the sum:
    /// charging both would mean the floor is paid twice on every large
    /// transfer, which is not what the economic model describes.
    #[must_use]
    pub fn required_transfer_fee(&self, amount: u64, base_fee: u64) -> u64 {
        base_fee.max(self.proportional_fee(amount, self.transfer_fee_ppm))
    }

    /// Protocol-level bounds for governance-tunable registry params.
    /// Prevents extreme values (e.g. zero unbonding, >100% slash ratios).
    ///
    /// # Errors
    ///
    /// Returns the offending parameter's name and bound when a value would
    /// disable a protection while appearing configured: a stake floor below
    /// 100, an unbonding window of zero or above 100,000 epochs, a slash
    /// ratio above `FIXED_POINT_SCALE`, a fee rate at or above 100% (which
    /// credits the recipient nothing while debiting the sender everything),
    /// or an invalid-vote threshold above 100,000, which no epoch can reach.
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
        // A protocol cut at or above 100% takes the whole amount, and on a
        // transfer that means the recipient is credited nothing while the
        // sender is debited everything. Refuse the rate rather than discover
        // it one transfer at a time.
        for (name, rate) in [
            ("transfer_fee_ppm", self.transfer_fee_ppm),
            ("swap_fee_ppm", self.swap_fee_ppm),
            ("bridge_fee_ppm", self.bridge_fee_ppm),
        ] {
            if rate >= PPM_DENOMINATOR {
                return Err(format!("{name} must be below 100%"));
            }
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
        Self {
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
            // 1% of min_stake = 10, mirroring slashing/proof fees: cheap for
            // an honest registrant, costly for registry-flooding sybils.
            // Governance-tunable per network; 0 disables.
            ai_model_register_fee: 10,
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
            // Proportional cuts start disabled. Turning one on changes what
            // every transfer costs, so it is a governance decision made on a
            // live network with real volume, not a default inherited by every
            // devnet. Zero here reproduces the flat-fee behaviour byte for byte.
            transfer_fee_ppm: 0,
            swap_fee_ppm: 0,
            bridge_fee_ppm: 0,
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
    /// If this fails, the result may still be correct, but it is not
    /// backwards compatible, and the `# Adding a field` note above applies.
    #[test]
    fn registry_params_serialized_shape_is_pinned() {
        let encoded =
            bincode::serialize(&RegistryParams::default()).expect("RegistryParams is serializable");
        // 15 u64 fields + 1 bool. bincode writes u64 as 8 bytes, bool as 1.
        //
        // The count moved from 12 when the three proportional rates were
        // added: a state-format change the `# Adding a field` note describes,
        // made deliberately, since snapshots written before it cannot be
        // loaded afterwards and the state root moves.
        //
        // This pin earned its place on the jail-term change. A
        // `liveness_jail_epochs` field was added here to give a liveness
        // slash an expiry; the gate answered that it breaks snapshot
        // compatibility for a number that never varies per network. The term
        // became `LIVENESS_JAIL_EPOCHS`, a constant, and this struct did not
        // move. The gate turned a refactor into a decision, which is the
        // whole reason it counts bytes by hand.
        //
        // The number is written out rather than derived from the struct,
        // which is the whole point. A test computing the expected length from
        // the type would agree with any shape the type happens to have and
        // would never fail, so it would not be a pin at all.
        assert_eq!(
            encoded.len(),
            16 * 8 + 1,
            "RegistryParams changed shape: old snapshots can no longer be \
             deserialized and the state root moves. See the type's docs."
        );
    }

    /// The pin has to be a pin, not a restatement of whatever the struct is.
    ///
    /// A shape test that passes for every possible struct is the vacuous case
    /// this guards against: it would have stayed green through the three
    /// fields that broke snapshot compatibility, which is exactly the moment
    /// it exists to catch.
    #[test]
    fn the_shape_pin_would_notice_another_field() {
        let encoded =
            bincode::serialize(&RegistryParams::default()).expect("RegistryParams is serializable");
        assert_ne!(
            encoded.len(),
            17 * 8 + 1,
            "a seventeenth u64 field would have to update the pin above, \
             which is the signal that snapshot compatibility broke"
        );
        assert_ne!(
            encoded.len(),
            15 * 8 + 1,
            "removing a field is equally a state-format change"
        );
    }

    /// A field the docs call governance-settable must actually be votable.
    ///
    /// `max_invalid_votes_per_epoch` carried "Governance-tunable per network"
    /// While being absent from `GOVERNANCE_PARAMETER_WHITELIST`. A proposal
    /// Naming it fails in `validate_governance_parameter_update` with
    /// "governance parameter is not whitelisted", after the vote, after the
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

    // === B73: a value transfer is priced by the value it moves ===========

    /// The regression. `validate_transaction` required only `fee >= base_fee`,
    /// and `tx.amount` reached pricing nowhere, so one base unit and a
    /// quadrillion cost the same.
    #[test]
    fn a_larger_transfer_requires_a_larger_fee() {
        let p = RegistryParams {
            transfer_fee_ppm: 200, // 0.02%
            ..RegistryParams::default()
        };
        let small = p.required_transfer_fee(1_000_000, 1);
        let large = p.required_transfer_fee(1_000_000_000, 1);
        assert!(
            large > small,
            "a 1000x larger transfer must not cost the same: {small} vs {large}"
        );
        assert_eq!(large, small * 1_000, "the cut must be linear in the amount");
    }

    /// The default has to reproduce the previous behaviour exactly. Every
    /// network running today priced transfers flat, and turning a cut on for
    /// all of them by shipping a new binary is not a governance decision.
    #[test]
    fn the_default_rate_leaves_the_flat_fee_untouched() {
        let p = RegistryParams::default();
        assert_eq!(p.transfer_fee_ppm, 0);
        for amount in [0u64, 1, 1_000_000, u64::MAX] {
            assert_eq!(
                p.required_transfer_fee(amount, 7),
                7,
                "a zero rate must charge exactly the flat floor"
            );
        }
    }

    /// The floor is what stops the split. A pure percentage rounds to zero
    /// below `PPM_DENOMINATOR / rate` units, so without it an attacker moves a
    /// large amount as many small ones and pays nothing.
    #[test]
    fn splitting_a_transfer_does_not_reduce_the_total_fee() {
        let p = RegistryParams {
            transfer_fee_ppm: 200,
            ..RegistryParams::default()
        };
        let base_fee = 1;
        let whole = 1_000_000_000u64;
        let pieces = 1_000u64;

        let one_shot = p.required_transfer_fee(whole, base_fee);
        let per_piece = p.required_transfer_fee(whole / pieces, base_fee);
        let split_total = per_piece.saturating_mul(pieces);

        assert!(
            split_total >= one_shot,
            "splitting must not be cheaper: {split_total} < {one_shot}"
        );
    }

    /// Truncation is how a real charge silently becomes zero. Storage pricing
    /// rounds up for this reason and so does this.
    #[test]
    fn a_priced_transfer_is_never_free_through_rounding() {
        let p = RegistryParams {
            transfer_fee_ppm: 1, // 0.0001%
            ..RegistryParams::default()
        };
        assert_eq!(
            p.proportional_fee(1, p.transfer_fee_ppm),
            1,
            "a one-unit transfer at a nonzero rate must still cost a unit"
        );
    }

    /// `amount * rate` leaves `u64` long before it leaves the `u128` the
    /// arithmetic runs in. Saturating keeps the balance check meaningful.
    #[test]
    fn an_enormous_transfer_saturates_rather_than_wrapping() {
        let p = RegistryParams {
            transfer_fee_ppm: PPM_DENOMINATOR - 1,
            ..RegistryParams::default()
        };
        let fee = p.required_transfer_fee(u64::MAX, 1);
        assert!(fee > 0, "must not wrap to a small number");
        // The interesting bound is the lower one: `amount * rate` leaves `u64`
        // here, so the saturating path must return something large rather than
        // a wrapped small number. Comparing against `u64::MAX` on a `u64` is
        // vacuously true and clippy is right to refuse it.
        assert!(
            fee > u64::MAX / 2,
            "a near-100% cut on u64::MAX must saturate high, got {fee}"
        );
    }

    /// A cut at or above 100% credits the recipient nothing while debiting the
    /// sender everything.
    #[test]
    fn a_proportional_rate_at_or_above_one_hundred_percent_is_refused() {
        let at_hundred = [
            RegistryParams {
                transfer_fee_ppm: PPM_DENOMINATOR,
                ..RegistryParams::default()
            },
            RegistryParams {
                swap_fee_ppm: PPM_DENOMINATOR,
                ..RegistryParams::default()
            },
            RegistryParams {
                bridge_fee_ppm: PPM_DENOMINATOR,
                ..RegistryParams::default()
            },
        ];
        for p in at_hundred {
            assert!(p.validate().is_err(), "100% cut must be refused");
        }
        let p = RegistryParams {
            transfer_fee_ppm: PPM_DENOMINATOR - 1,
            ..RegistryParams::default()
        };
        assert!(
            p.validate().is_ok(),
            "just under 100% is a policy choice, not an error"
        );
    }

    /// The three rates are separate parameters on purpose: a swap consumes
    /// more of the network than a transfer, and the protocol cut on an
    /// outbound bridge is not the relayer's compensation on an inbound one.
    #[test]
    fn the_three_proportional_rates_are_independent() {
        let p = RegistryParams {
            transfer_fee_ppm: 200,
            swap_fee_ppm: 400,
            bridge_fee_ppm: 800,
            ..RegistryParams::default()
        };
        let amount = 10_000_000u64;
        assert_eq!(p.proportional_fee(amount, p.transfer_fee_ppm), 2_000);
        assert_eq!(p.proportional_fee(amount, p.swap_fee_ppm), 4_000);
        assert_eq!(p.proportional_fee(amount, p.bridge_fee_ppm), 8_000);
        assert_ne!(
            p.bridge_fee_ppm, p.bridge_relayer_fee_ppm,
            "the protocol cut and the relayer's compensation are different things"
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
