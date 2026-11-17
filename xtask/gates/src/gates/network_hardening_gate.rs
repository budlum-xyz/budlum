//! Required named tests: network hardening.
//!
//! Ported from scripts/check-*.sh as a member of the "required named tests"
//! family. The cargo test log must show every name in [`TESTS`] followed by
//! `ok`, or the gate fails naming the first missing test. Behaviour parity
//! with the shell gate is proven by the shared [`super::named_tests`]
//! self-test, which stages a fake log.

use std::path::Path;

pub(crate) const TESTS: &[&str] = &[
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
    // The eclipse bound covers both address families, and a
    // peer-supplied length prefix is a claim the decoder budgets for instead
    // of trusting.
    "eclipse_bound_covers_ipv6_peers",
    "ipv4_mapped_address_is_not_a_new_subnet",
    "kademlia_refuses_private_addresses_on_public_network",
    "p2p_bincode_is_bounded",
    // Live testnet P2P connection, multi-chunk /sync, fork-recovery, and
    // 2-hop BFT finality locks.
    "duplicate_connection_event_for_admitted_peer_is_not_rejected_at_subnet_cap",
    "plan_sync_headers_skips_shared_locator_prefix_and_caps_fork_and_forward_windows",
    "unjoined_next_height_block_and_connection_guards_are_wired",
    "unjoined_next_height_fork_sync_and_connection_guards_are_in_production_source",
    "deferred_votes_two_pass_replay_and_prevote_retry_until_precommit_quorum",
    "failed_prevote_publish_still_advances_high_water_mark_and_blocks_reorg_equivocation",
    "write_vote_history_file_persists_atomically_and_reports_unwritable_target",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "Network hardening")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "Network hardening")
}
