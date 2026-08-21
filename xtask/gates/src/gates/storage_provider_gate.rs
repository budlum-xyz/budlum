//! Required named tests: storageprovider.
//!
//! Ported from scripts/check-*.sh as a member of the "required named tests"
//! family. The cargo test log must show every name in [`TESTS`] followed by
//! `ok`, or the gate fails naming the first missing test. Behaviour parity
//! with the shell gate is proven by the shared [`super::named_tests`]
//! self-test, which stages a fake log.

use std::path::Path;

const TESTS: &[&str] = &[
    "storage_provider_put_get_roundtrip",
    "storage_provider_rejects_invalid_range",
    "storage_provider_prove_settle_roundtrip",
    "storage_provider_rejects_forged_proof_range_hash",
    "lifecycle_happy_path_settled",
    "lifecycle_challenge_can_miss_or_slash",
    "lifecycle_rejects_skip_open_to_settled",
    "lifecycle_terminal_states_are_final",
    "registry_lifecycle_projection_tracks_challenge_and_slash",
    "registry_lifecycle_projection_tracks_expiry",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "StorageProvider")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "StorageProvider")
}
