# Lane C live verification (WP-03)

Scope: ledger rows whose "Kapatan IP" column names IP-26 to IP-35, IP-44 or IP-49 to IP-60. Live branch: `main` at `14d9a18` (see `baseline.md`). Status vocabulary and ID blocks are defined in `baseline.md`. New findings use BLG-332 to BLG-363.

Method: the old ledger is outside the repository, so each claim is derived from the directive title, then located on the live branch by content (identifier search, function reading). Line numbers are never used as evidence. "Test name" is the permanent regression test (Previously fixed), the repro test on branch `audit/repro-c` (Verified), or `owed: <name>` when a repro is still to be written (Verified (static)).

Related files: `docs/audit/live/engine-inventory.md`.

## Special audits

Filled in below the findings table (sections "Special audit 1" to "Special audit 5").

## Findings

| ID | Live status | Test name | Evidence | Closing package | Severity suggestion | English title | Notes |
|---|---|---|---|---|---|---|---|
