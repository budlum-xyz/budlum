//! Required named tests: poa compliance.
//!
//! Ported from scripts/check-*.sh as a member of the "required named tests"
//! family. The cargo test log must show every name in [`TESTS`] followed by
//! `ok`, or the gate fails naming the first missing test. Behaviour parity
//! with the shell gate is proven by the shared [`super::named_tests`]
//! self-test, which stages a fake log.

use std::path::Path;

const TESTS: &[&str] = &[
    "poa_compliance_rejects_permissionless_screening",
    "poa_compliance_screening_updates_status",
    "poa_compliance_requires_admin_for_freeze",
    "poa_compliance_freeze_is_poa_only",
    "poa_compliance_audit_log_is_append_only",
    "poa_compliance_rejects_zero_evidence_hashes",
    "poa_compliance_records_travel_rule_metadata_hash",
    "poa_compliance_rejects_permissionless_travel_rule_metadata",
    "poa_compliance_exports_audit_csv",
    "poa_compliance_exports_audit_json",
];

pub fn run(_root: &Path, log: &Path) -> Result<String, String> {
    super::named_tests::check_log(log, TESTS, "PoA compliance")
}

pub fn self_test() -> Result<String, String> {
    super::named_tests::self_test(TESTS, "PoA compliance")
}
