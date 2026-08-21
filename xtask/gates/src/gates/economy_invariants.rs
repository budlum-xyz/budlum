//! Required named tests: economy invariant.
//!
//! Ported from scripts/check-*.sh as a member of the "required named tests"
//! family. The cargo test log must show every name in [`TESTS`] followed by
//! `ok`, or the gate fails naming the first missing test. Behaviour parity
//! with the shell gate is proven by the shared [`super::named_tests`]
//! self-test, which stages a fake log.

use std::path::Path;

const TESTS: &[&str] = &[
    "base_fee_increase_is_bounded",
    "base_fee_decrease_is_bounded",
    "max_fee_below_base_fee_rejected",
    "effective_tip_cannot_exceed_priority_or_cap",
    "legacy_fee_maps_to_zero_tip",
    "reward_pool_default_schedule_valid",
    "reward_pool_conserves_budget",
    "reward_pool_rounding_remainder_deterministic",
    "total_bud_committed_counts_stake_and_unbonding",
    "supply_capacity_remaining_uses_committed_denominator",
    "flat_fee_validation_uses_base_fee_floor",
    "flat_fee_rejects_priority_fee",
    "flat_fee_rejects_max_fee_divergence",
    "fee_field_tampering_invalidates_signature",
    "legacy_eip_preview_has_no_balance_side_effects",
    "legacy_eip_preview_cannot_mint_tip",
    "nonzero_block_reward_config_cannot_mint",
    "block_reward_is_disabled_even_below_supply_cap",
    "epoch_transition_does_not_mint_validator_yield",
    "governance_cannot_enable_block_emission",
    "flat_fee_block_credits_producer_once_after_metabolic_burn",
    "fee_distribution_treasury_split_is_deterministic",
    "fee_distribution_rejects_underpriced",
    "fee_distribution_zero_treasury_rate",
    "fee_distribution_full_treasury_rate",
    "fee_distribution_large_fee_exercises_treasury",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "Economy invariant")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "Economy invariant")
}
