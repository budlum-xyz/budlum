# Findings ledger

This is the shared append-only ledger for findings discovered after BLG-267.
The original register remains the directive's section 14 until the live-status
packages reconcile it. Rows from other deliveries must be preserved on rebase.

## Rules

1. An identity is never reused or renumbered.
2. Severity is Critical, High, Medium or Low.
3. A fix is not closed until its regression has an observed red result before
   the fix, an executed green result after it, and a CI run identifier.
4. A commit SHA identifies proposed code, not executed evidence.
5. Conflicting reservations in parallel PRs are reconciled explicitly before
   merge; a silent renumbering is not an acceptable resolution.

## New findings

IDs BLG-281 through BLG-285 were checked against all 62 live PR bodies and
reserved in PR #77 before their records were written. BLG-286 and BLG-287 were
checked against the subsequent 63-PR body snapshot and reserved in PR #77 before
this addendum. BLG-288 through BLG-290 were reserved in PR #77 for the independent
mobile/node compatibility review before their rows were added. Existing
reservations through BLG-280 are not changed.

| Identity | Severity | Location | Finding | Regression / evidence | Closing package | Status |
|---|---|---|---|---|---|---|
| BLG-281 | High | `EeClient::connect`, `EeClient::drive` | A reconnect handshake gets a separate budget, and socket read timeouts restart on every received byte. A dribbling peer can extend a request beyond the watchdog. | `uel_abi_handshake_dribble_uses_an_absolute_deadline`, `uel_abi_response_dribble_uses_an_absolute_deadline`, `uel_abi_reconnect_handshake_shares_the_request_budget`; tests added in `980a887`, proposed fix `12615f6`. Local green at `3863171` (Rust 1.99.0, external directory source); pinned-toolchain CI pending. | WP-09 | open |
| BLG-282 | Medium | `EeClient::drive` | `Instant::now() + self.timeout` can panic for a public timeout value that cannot be represented by the platform clock. | `uel_abi_unrepresentable_deadline_does_not_panic`; test added in `980a887`, proposed checked-clock fix `12615f6`. Local green at `3863171` (Rust 1.99.0, external directory source); pinned-toolchain CI pending. | WP-09 | open |
| BLG-283 | High | `EeClient::{validate_deploy,execute,query}` | An empty, wrong-type or wire-invalid final response returns an error after `drive` succeeds, but leaves the connection reusable. | `uel_abi_unusable_final_response_poisons_the_connection`; test added in `980a887`, proposed fix `12615f6`. Local green at `3863171` (Rust 1.99.0, external directory source); pinned-toolchain CI pending. | WP-09 | open |
| BLG-284 | High | `RemoteHost::call`, `serve_connection` | Worker host calls have no absolute I/O budget. Empty, wrong-type and undefined-error replies can become ordinary `HostError` values and then deterministic engine reverts. | `uel_abi_worker_host_reply_has_a_watchdog`, `uel_abi_worker_rejects_malformed_host_replies`, `uel_abi_valid_host_refusal_remains_deterministic`; tests added in `749cdbe`, proposed fix `4ff2cc2`. Local green at `3863171` (Rust 1.99.0, external directory source); pinned-toolchain CI pending. | WP-09 | open |
| BLG-285 | Medium | `.github/workflows/ci.yml`, standalone crate checks | The ABI crate's socket tests are not invoked by the standalone-crate job. The explorer format step is attached to that job across a job-boundary comment rather than to an explorer job. | YAML parse inspection confirms the misplaced step; proposed repair and ABI fmt/clippy/test commands in `980a887`. Local ABI fmt/clippy/tests green at `3863171`; workflow execution pending. | WP-42 / WP-09 | open |
| BLG-286 | High | `serve_connection`, worker frame reads | An accepted connection can send the first byte of a frame and then withhold the rest indefinitely; the worker has no deadline for a started frame. | `uel_abi_worker_partial_frame_has_a_deadline_after_first_byte`; test added in `c6f5260`, seed corrected in `31a530e`, proposed fix `8a8688f`. Local green at `3863171` (Rust 1.99.0, external directory source); pinned-toolchain CI pending. | WP-09 | open |
| BLG-287 | High | `serve_connection`, `ValidateDeployRequest` | Deploy validation runs outside `catch_unwind`, unlike execute and query. An engine panic can unwind the worker service instead of closing the connection as a controlled transport failure. | `uel_abi_worker_catches_deploy_validation_panics`; test added in `c6f5260`, proposed fix `8a8688f`. Local green at `3863171` (Rust 1.99.0, external directory source); pinned-toolchain CI pending. | WP-09 | open |
| BLG-288 | High | PR #70 `presence_message`, PR #82 `presence_preimage` | Node and mobile length-prefix different fields before SHA3-256, so the same presence signal signs different bytes and cannot verify across implementations. | Executed byte-level Python reproduction and differing digests in `docs/audit/REVIEW_2.md`; shared Rust golden vector and cross-implementation BLS test pending. | WP-13 / WP-11 | open |
| BLG-289 | High | PR #82 `CustodyProofBatch`, `ShareStore::answer`; node `StorageTxV3` | Mobile proof batches omit the object key required by the node and select audits by segment/position alone, allowing a wrong-object selection. | Type and lookup evidence in `docs/audit/REVIEW_2.md`; object-collision regression pending. | WP-11 / WP-20 | open |
| BLG-290 | High | PR #82 `DutyTx::ReleaseShares`, PR #45 `StorageTxV3::ReleaseShares` | Mobile release carries only process-local share ids; it cannot encode the chain object/share/quota payload, so local deletion need not trigger chain repair. | Contract comparison in `docs/audit/REVIEW_2.md`; shared payload and round-trip regression pending. | WP-11 / WP-20 / WP-22 | open |

## Local execution record

No row is closed by this delivery. A CI run identifier and pinned-toolchain
red-to-green evidence are still required.

The workspace recovered with the previously pushed tracked changes present as
uncommitted modifications and the new audit/test files untracked. They were
stashed, the fixed branch was fast-forwarded to its remote head, and every
stashed file was compared with the recovered head. The stash is retained; it
contains no unique source deliverable.

An external check environment was then built outside Git: Rust/cargo/rustfmt/
Clippy 1.99.0 from the npm toolchain-component mirror, exact-version upstream
GitHub dependency archives where available in a Cargo directory source, and
`grpcio-tools` protoc. The external manifest points at the repository's ABI
source and tests; it is not a crates.io lockfile or Rust 1.97.1 verification.
One transitive candidate (`equivalent`) resolved to 1.0.1 from its upstream
default branch because the locked 1.0.3 archive was not available; Windows-only
dependency sections were removed from external dependency copies for the Linux
check. Repository manifests, pins, features and gates were not changed.

Executed results at `3863171`:

```text
cargo test --offline --tests --no-fail-fast: 25 passed, 0 failed, 0 ignored
cargo clippy --offline --all-targets -- -D warnings: passed
rustfmt --edition 2021 --check: passed
git diff --check: passed
```

The first local compile exposed a real inherited edit error: `begin_request`
matched `Option` against the checked `Result` from `deadline_after`; fixed in
`57bed73`. The first local test run then exposed two regression-harness errors:
the reconnect peer closed before the shared budget expired, and the worker frame
test expected `Frame(Timeout)` although the transport maps deadlines to
`TransportError::Timeout`; corrected in `2dd8a09` and `f43a46a`. Strict Clippy
exposed `explicit_auto_deref` in `RemoteHost::call`; fixed in `ef9f590`. The ABI
integration-test panic channel was then budgeted in the suppression gate in
`3863171`, matching the existing ABI test files.

These are executed local results, not CI. The original pre-fix red runs for
BLG-281 through BLG-287 were not observed before their fixes; the ledger therefore
does not claim directive S-3 closure.

## Identifier collisions

BLG-288 through BLG-290 are qualified in this ledger as **PR #77** findings.
Later live PR bodies also use some of those numbers for unrelated records.
PR #88 and PR #91 explicitly cross-reference the PR #77 meanings, so this delivery
does not silently renumber them. Merge reconciliation must preserve the qualified
references or assign canonical identifiers with an explicit crosswalk.
