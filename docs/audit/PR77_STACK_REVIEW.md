# PR #77 worker/mobile compatibility integration review

| Field | Value |
|---|---|
| Reviewed source | PR #77, `3c8a45fb182b6c7b890147425a09e6eeee0ac8b0` |
| Integration target | PR #140 / `arena/8f90e12c-budlum` |
| Source check inventory | 1 failed, 43 cancelled, 55 pending and 3 skipped checks in the captured inventory. The failed arm64 cross-arch check is not represented as diagnosed or fixed. |
| Current execution evidence | Static/source checks and Python integration audit; no Rust toolchain, Cargo test, cross-arch run or node/mobile wire rehearsal was available |

## Relationship to PR #80 and PR #88

PR #80 carried PR #77 only through the older `bec1cf8` checkpoint. The PR #80
integration adapted the worker-boundary behavior into the current tree; it did not
make the later #77 commits ancestral. This review covers the remaining delta through
`3c8a45fb`.

The worker implementation differs from #77 only where the current shared
`host::panic_digest`/`panic_message` implementation is deliberately retained. The
current test adaptations are also retained: Unix cfg gates, stale-socket removal,
a peer kept open through the deadline race, the corrected `TransportError::Timeout`
class and scheduler headroom. These avoid restoring older test races or weaker
platform guards.

The later required-fee and formatting/indexing changes were already present. The
current `.gitignore` has both depth-independent and root-anchored directive rules;
the older one-rule addition is unnecessary. The removed root helper, historical PR
inventories and older audit/ledger documents are not restored. Current CI already
runs format, all-target Clippy and all tests for `crates/uel-abi`.

## Remaining change integrated here

`xtask/gates/src/gates/suppressions_are_justified.rs` now carries the source's ten
justified budgets: one `clippy::unwrap_used` and one `clippy::expect_used` occurrence
for each of `frames.rs`, `transport.rs`, `transport_deadlines.rs`,
`transport_host_guards.rs` and `transport_worker_frames.rs`. They describe the
existing test-only panic reporting channel. They do not suppress production lints,
raise a count or conceal a new allowance. **BLG-309** records the missing-budget
integration defect and remains open pending the actual gate and pinned Rust CI.

## Finding cross-reference

PR #77's identifiers are not silently reused as new canonical identities:

| PR #77 meaning | Current record |
|---|---|
| BLG-281 client deadline reset / BLG-282 unchecked clock addition / BLG-286 started worker frames | BLG-303 |
| BLG-283 unusable final responses / BLG-284 malformed host callbacks | BLG-304, with the callback deadline leg in BLG-303 |
| BLG-287 deploy-validation panic | BLG-305 |
| BLG-285 ABI CI/suppression visibility | CI wiring retained; missing suppression budgets are BLG-309 |
| PR #77-qualified BLG-288 presence preimage incompatibility | Still open in `FINDINGS.md`; the G-5 fixture exposes rather than hides it |
| PR #77-qualified BLG-289 proof object identity | Mobile object-keyed duties are locally corrected in the PR #88 record; signed node/wire acceptance remains outstanding |
| PR #77-qualified BLG-290 release payload | Still open; process-local release ids are not represented as chain share/quota payloads |

No signed node/mobile interoperability, chain release transaction, connected worker
supervision or testnet result is claimed by closing the source pull request.

## Executed checks

- Verified ten budget rows against the five test files and their one crate-level
  allowance per lint; no production suppression was added.
- Tree-sitter parsed the changed suppression gate and retained worker files earlier
  in this worker integration; no syntax errors were found.
- Integration audit: 14/14 current-tree checks passed and its 14 injected canaries
  each refused the intended violation during the worker integration.
- Diff whitespace/error checks passed.

Rust 1.97.1 format/Clippy/test execution, the actual suppression-gate run, the
source's failed arm64 check diagnosis, cross-platform transport evidence and
node/mobile wire acceptance remain outstanding. BLG-288 through BLG-290 retain
their existing PR-qualified open meanings; BLG-303 through BLG-309 also remain open
pending pinned execution evidence.
