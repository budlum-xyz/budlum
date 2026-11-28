//! Required exact named tests: the ten APK acceptance checks.
//!
//! The tests live in `tests/garden/garden_apk.rs` and run the phone's real
//! Garden library (`budlum_garden_ffi` through `garden-phone`) against a real
//! `budlum-core` node. The cargo test log must contain the full line
//! `test <name> ... ok` for every name below, so a test that was renamed,
//! deleted or filtered out fails the gate instead of passing with nothing run.
//!
//! `garden_apk_permissions_denied` is in the list on purpose: it is the one
//! check that needs an Android sandbox. Leaving it out would let the suite
//! report a clean sheet while the device-only gap went unmentioned; keeping it
//! in means the gate names the gap.

use std::path::Path;

pub(crate) const TESTS: &[&str] = &[
    "garden_apk_single_file",
    "garden_apk_clean_install",
    "garden_apk_first_run",
    "garden_apk_host_scenario",
    "garden_apk_join_by_link",
    "garden_apk_share",
    "garden_apk_clipboard_join",
    "garden_apk_background",
    "garden_apk_cleanup",
    "garden_apk_permissions_denied",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::exact_named_tests::check_exact_log(log, TESTS, "garden-apk")
}

pub fn self_test() -> Result<String, String> {
    super::exact_named_tests::self_test_exact(TESTS, "garden-apk")
}
