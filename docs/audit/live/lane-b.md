# Lane B live verification: storage (WP-02)

Live branch `main`, commit `14d9a18130b5147e9f0e9412e57b3f8b31b45449` (see `baseline.md`). Scope: ledger rows whose closing package is IP-06, IP-07, IP-10, IP-18 to IP-25 or IP-45, plus the WP-02 special audits at the end of this file.

Status vocabulary: see `baseline.md`. Conventions used below:

- "test name" is a permanent green test in `src/tests/audit_lane_b.rs` (Previously fixed), a red repro on branch `audit/repro-b` (Verified, with commit SHA in notes), or `-` when none exists yet.
- `source lock` means the green test reads the source file and asserts the guard is present. It is used where the fixed code lives in a standalone crate that the main crate cannot link. A behavioural test is still owed for those rows.
- Severity suggestion keeps the old ledger severity unless the notes say otherwise.

## Findings

| ID | Live status | Test name | Evidence (file + function) | Closing package | Severity suggestion | English title | Notes |
|---|---|---|---|---|---|---|---|
| BLG-045 | Closes by removal | - | src/domain/storage_deal.rs::StorageRegistry::open_challenge and answer_challenge (file is "Sil" in directive 5.2) | IP-07 | Kritik | StorageRegistry::open_challenge permanent 1-atom challenge immunity and unverified challenge proof | Code present on live. Partly mitigated: open_challenge now scales the opener bond with the range (required_opener_bond, OpenerBondBelowRangeCost). answer_challenge still trusts the off-chain range hash (doc comment: full hash verification deferred). Moot once the registry is deleted. |
| BLG-046 | Closes by removal | - | src/domain/storage_deal.rs::StorageRegistry::open_deal and prune_content ("Sil") | IP-07 | Kritik | open_deal source/dictionary verification bypass and prune_content permanent collateral lock | Code present on live. prune_content now returns (operator, bond) pairs for the caller to credit, so the collateral lock is mitigated. open_deal verification bypass was not re-tested. Deleted by WP-07. |
