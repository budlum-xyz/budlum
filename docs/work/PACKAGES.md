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

### PR #88 verification checkpoint

- Stack: #82 -> #85 -> #88. Parent #85 remains open and unchanged.
- Implementation head: `d6b7457acc19f6b64499adf931d31b55326bac14`.
- New implementation: checked quota/id arithmetic, replay/conflicting-symbol
  admission refusals, object-keyed proof duties, inherited stable-build and
  strict-Clippy repairs. #85's fixes are carried intact, not reimplemented.
- Local source verification: 23 mobile tests pass (11 library, 12 integration),
  zero ignored; mobile fmt and all-target Clippy `-D warnings` pass with Rust
  1.99.0 and external exact-version upstream sources. Rust 1.97.1 CI is not
  verified. No CI was polled or awaited.
- BLG-298 through BLG-301 remain open pending CI evidence. PR #77 / BLG-289
  has locally corrected object-selection/retention legs, not a full closure.
- Presence encoding and chain release-payload compatibility remain blocked
  as described in `docs/audit/MOBILE_CORE_REVIEW.md`. Shared types, signed
  wire round trips and durable release acknowledgement are still required.
- WP-11 stays in progress. No package or TLG completion is claimed.
