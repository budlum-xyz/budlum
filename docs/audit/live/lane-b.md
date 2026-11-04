# Lane B live verification: storage (WP-02)

Live branch `main`, commit `14d9a18130b5147e9f0e9412e57b3f8b31b45449` (see `baseline.md`). Scope: ledger rows whose closing package is IP-06, IP-07, IP-10, IP-18 to IP-25 or IP-45, plus the WP-02 special audits at the end of this file.

Status vocabulary: see `baseline.md`. Conventions used below:

- "test name" is a permanent green test in `src/tests/audit_lane_b.rs` (Previously fixed), a red repro on branch `audit/repro-b` (Verified, with commit SHA in notes), or `-` when none exists yet.
- `source lock` means the green test reads the source file and asserts the guard is present. It is used where the fixed code lives in a standalone crate that the main crate cannot link. A behavioural test is still owed for those rows.
- Severity suggestion keeps the old ledger severity unless the notes say otherwise.

## Findings

| ID | Live status | Test name | Evidence (file + function) | Closing package | Severity suggestion | English title | Notes |
|---|---|---|---|---|---|---|---|
