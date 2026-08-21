//! Required named tests: network hardening.
//!
//! Ported from scripts/check-*.sh as a member of the "required named tests"
//! family. The cargo test log must show every name in [`TESTS`] followed by
//! `ok`, or the gate fails naming the first missing test. Behaviour parity
//! with the shell gate is proven by the shared [`super::named_tests`]
//! self-test, which stages a fake log.

use std::path::Path;

const TESTS: &[&str] = &[
    "rate_limit_exhaustion_uses_dedicated_penalty",
    "repeated_rate_limit_exhaustion_bans_peer",
    "peer_rate_limit_security_profile",
    "eclipse_subnet_bound_rejects_fifth_peer",
    "eclipse_disconnect_frees_subnet_slot",
    "eclipse_peer_accounting_is_idempotent",
    "rpc_auth_required_by_default",
    "max_message_size_rejected",
    "eclipse_bound_still_active",
    "multinode_smoke_artifacts_present",
    "chaos_network_partition_isolates_groups",
    "chaos_byzantine_block_rejected",
    "chaos_eclipse_single_peer_isolation",
    "chaos_sybil_subnet_bound_rejects_excess",
    "chaos_ban_ttl_allows_reconnect_after_expiry",
    "chaos_reputation_fuzz_decay",
    "outbound_subnet_diversity_rejects_excess",
    "reputation_score_clamped_under_repeated_penalties",
    "h5_score_map_ceiling_holds_on_every_entry_point",
    "h5_score_map_ceiling_is_load_bearing",
    "h5_ceiling_refuses_rather_than_evicting_a_ban",
    "h5_tracked_peer_still_scored_when_map_is_full",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "Network hardening")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "Network hardening")
}
