# Work packages

English status ledger. Additive. Each package's last pull request updates
its row. This file does not claim a package is complete without a commit
SHA and a CI run number.

| Package | Lane | Status | Pull requests | Notes |
|---|---|---|---|---|
| WP-11 | D | in progress, 2/N | #82 | Mobile core duty engine. Types crate, light client, UniFFI and libp2p are later slices. BLG-022, BLG-257 and BLG-259 stay open. |

## WP-11 continuation: admission and audit boundaries

- Parent: #82 at `5685e03d87c257e7e1ecc6fd3355eee5cebdbf94`.
- Session branch: `arena/dc0a724c-budlum`; a stacked PR targets the parent branch.
- Locks: `mobile/core/`; additive audit record
  `docs/audit/MOBILE_CORE_REVIEW.md` and this package record.
- Test-first regressions cover assignment identity, object-scoped audits,
  refusal atomicity and quota/free-space boundaries. The first quota overflow
  regression is executed red. No finding is closed and WP-11 is not complete.
- Evidence and environment restrictions: `docs/audit/MOBILE_CORE_REVIEW.md`.

- Concurrent continuation #85 was discovered after the first claim. PR #88
  now continues #85 without recreating its fixes. The inherited presence
  test compile error was reproduced and corrected. Local checks use upstream
  GitHub dependency archives; CI remains authoritative.
