# Budlum audit report

## Current measured continuation evidence

This section supersedes the active/pending wording in the older snapshot below, without rewriting its historical outcomes. No overall CI-green or acceptance claim is made.

- Final local Garden source `2574882aa35d4f3787e53aa1911af7b20df6b760` contains numbered commits 26 through 28. They are still unpushed at this snapshot. Debian: network 17/17, Garden library 121/121, separate-process scenario 18/18 and real-NAT 1/1, all with zero ignored tests and exit 0. Formatting, scenario/NAT gate self-tests and log checks, English-tree and Unicode-dash gates pass. All-target/all-feature `clippy -D warnings` passes in 10m55s.
- The complete `cargo test --all-features` invocation is now running on the same immutable source, with pre/post-source assertions and separate evidence under `/home/user/validation/garden/final-all-features/`. No outcome is yet observed. Targeted Garden success is not substituted for that suite or CI.
- Ubuntu Base 24.04.5 userland runs the final Debian-built library: empty DNS network 17/17 and Garden library 121/121; configured DNS network 17/17. Its configured-DNS scenario starts real separate production processes and passes 18/18 in 121.12 seconds. This is not an Ubuntu-native build or separate Ubuntu kernel. Primary P2P startup with empty DNS still exits 1, so the Garden fallback only partially repairs B-0044.
- B-0041 is locally repaired by `f0fc88e0`, and B-0049's invite regression by `c1e9dfda`; neither is CI-closed. B-0042's canonical decoder remains absent from main. An independent B-0043 owned-frame patch is prepared outside the source tree under test: the exact read helper fails the same retained-frame assertion before the patch (101) and passes after it (0). Its staged network/type module harness passes 31/31, including a real stalled-consumer swarm, but the changed node consumer has not yet had a whole-project build or scenario execution.
- Main is freshly fetched at `1bd93561f78564f6ab325ec0066dd2da7d5e4a76`. Canonical B.U.D. 3.0 and the bounded decoder are still absent; only dependency-bound work is stopped. The storage requirement remains open as B-0050 / BLG-269.
- New B-0051 records a real upper-branch quality-job failure: CI 1845 measures 7,223 extra-clippy warnings against stale baseline 8,513. Preserve the gate and use an exact-source authoritative measurement before lowering a baseline; do not borrow another branch's count.
- New B-0052 / BLG-270 records reachable host-only admission authority, contrary to the Garden directive. The currently passing host-approval scenario proves that extra authority exists; it is not evidence of policy compliance.
- B-0053 records five audit prose lines rejected by the real Unicode-dash gate. Only punctuation is corrected; audit-sourced English/dash gates and both self-tests, formatting and diff checks now pass locally. A cross-revision English-gate false positive is explicitly excluded; no legitimate localization or baseline is weakened.
- The review-thread collector now paginates fully (#164: 123 threads/two pages; #126: 394/four pages). PR #198 has 15 new unresolved CodeRabbit threads on `1857ffd36254`, separately inventoried before any comment action. Strix and other reviews are not conflated. No review comment is resolved, deleted or answered as fixed by this evidence.

### Latest collected GitHub heads and checks

Collected at `2026-11-18T13:05:18.653880+00:00`. All six PR head OIDs match their branch targets at collection. This is a time-bound observation; refresh again before a push. Queued, pending, skipped, neutral and cancelled results are not success.

| PR | Head SHA | Check-run states | Unresolved threads, fully paginated | Merge state |
|---|---|---|---|---|
| #126 | `56cfddb4fede` | 2 cancelled; 4 in_progress; 1 neutral; 37 queued; 3 skipped; 105 success | 0 | blocked |
| #164 | `3467a0bababb` | 3 in_progress; 2 neutral; 56 queued; 24 skipped; 50 success | 0 | blocked |
| #183 | `df970fc98402` | 1 failure; 10 in_progress; 2 neutral; 60 queued; 29 skipped; 37 success | 0 | blocked |
| #194 | `22860424031a` | 97 queued; 1 skipped | 0 | unstable |
| #198 | `1857ffd36254` | 96 queued; 1 success | 15 | unstable |
| #200 | `2754c2c306c3` | 3 cancelled; 103 queued; 1 skipped | 0 | blocked |

Remote Garden's individually successful NAT 121 and Rust Quality 779 checks apply to `3467a0ba`, not to unpushed `2574882a`; CI 1839 remains queued. Audit PR #200 is verified open on `2754c2c3`; its CI 1848 is queued. No protection is bypassed and no main merge is performed during the freeze.

## Historical snapshot

GitHub snapshot: `2026-11-18T11:06Z`. Counts refer to check runs returned for each recorded head, not a claim that every required workflow passed. A queued run is not a passing run, so no row below is evidence of a green build.
The branch heads and check results can change. Refresh before every push or merge.

### Historical heads and checks

| PR | Head to base | Head SHA | Check-run summary | Unresolved threads | Strix approval | Merge state |
|---|---|---|---|---|---|---|
| [#126](https://github.com/budlum-xyz/budlum/pull/126) | `testnet` to `main` | `56cfddb4fede` | 17 success; 75 queued; 3 skipped or neutral; 5 running; 0 failed | 0 | no approval found | blocked |
| [#164](https://github.com/budlum-xyz/budlum/pull/164) | `garden` to `testnet` | `3467a0bababb` | 0 success; 76 queued; 24 skipped or neutral; 0 failed | 0 | no approval found | blocked |
| [#183](https://github.com/budlum-xyz/budlum/pull/183) | `budlum-stack` to `garden` | `a1de85ec6795` | 0 success; 89 queued; 11 skipped or neutral; 0 failed | 0 | no approval found | blocked |
| [#194](https://github.com/budlum-xyz/budlum/pull/194) | `budlum-consensus-of-consensuses` to `budlum-stack` | `365e02f297eb` | 0 success; 0 queued; 1 skipped or neutral; 0 failed | 0 | no approval found | dirty |
| [#198](https://github.com/budlum-xyz/budlum/pull/198) | `agg/phase-5-pcs-claims` to `budlum-consensus-of-consensuses` | `f45cd034d486` | 58 success; 33 queued; 5 failed (Coverage (nextest + llvm-cov, ratchet), Fork-Choice Invariants, Network Hardening) | 0 | no approval found | unstable |
| [#200](https://github.com/budlum-xyz/budlum/pull/200) | `audit/budlum-continuation-20261118` to `main` | `161b34d27696` | 0 success; 99 queued; 1 skipped or neutral; 0 failed | 0 | no approval found | blocked |

The `main` branch protection API lists `Strix Security Review` as a required status. Strix reports that the included review quota is exhausted. This is an external blocker; do not bypass branch protection.
A changes-requested review from CodeRabbit remains in the review history of #164, #183 and #194, and #200 now carries one too. See the follow-up record.

## Records

- [Plan and full file inventory](plan.md)
- [Strix review ledger](strix-ledger.md)
- [Garden network findings B-0041 through B-0043](findings/garden-network.md)
- [Garden resolver finding B-0044](findings/garden-dns.md)
- [PoSpace engine finding B-0045](findings/pospace.md)
- [Domain plugin wiring finding B-0046](findings/domain-plugin-wiring.md)
- [Dead-API gate finding B-0047](findings/dead-pub-api-gate.md)
- [Account bincode round trip, B-0048](findings/account-bincode-roundtrip.md)
- [VerifyMerkle gate and the deal-open envelope, B-0054](findings/verify-merkle-gate.md)
- [Garden invite regression, B-0049 / BLG-268](findings/garden-invite.md)
- [Garden B.U.D. 3.0 integration gap, B-0050 / BLG-269](findings/garden-storage.md)
- [Extra-clippy stale baseline, B-0051](findings/clippy-ratchet-baseline.md)
- [Garden host-only authority, B-0052 / BLG-270](findings/garden-host-authority.md)
- [Audit-note punctuation quality, B-0053](findings/audit-note-quality.md)
- [Garden acceptance step evidence](testnet/garden-acceptance.md)
- [Garden main-only dependency stop report and design](testnet/garden-main-only.md)
- [Supplied inventory reconciliation](testnet/inventory-drift.md)
- [Review summary follow-up](findings/review-summaries.md)
- [Debian execution record](findings/os-debian.md)
- [Ubuntu userland execution record](findings/os-ubuntu.md)
- [Testnet specification index](testnet/index.md)

## Snapshot refresh 2026-11-18 (late afternoon, Europe/Istanbul)

- Live PR heads: #126 `56cfddb4fede`, #164 `3467a0bababb` (2 failing checks: `Budlum Core library test` job 134729279818 and the Coverage ratchet, both red on the `garden::invite_refuses_non_canonical_hex_and_duplicate_peers` assertion at `src/garden/invite.rs:354`), #183 `f36491d2` after the B-0051 baseline repair push (CI not yet observed green), #194 `22860424031a`, #198 `1857ffd36254`, #201 `02de7030ac56` (VerifyMerkle gate fix). #200 carries the audit notes; PR #201 opened by this audit effort.
- CI runner starvation is the dominant state: on #194/#198/#200 the large majority of checks sit `queued`; on #126 111 success with 2 `cancelled` (Cross-Platform Digest macos-latest) and no failures; nothing in this snapshot is a green-merge claim.
- Local `cargo fmt --all -- --check` passes on `audit/budlum-continuation-20261118`. A local `cargo test --lib --all-features --no-run` was killed by the OOM killer with the test profile's `opt-level = 1` and debug info (2 GB RAM host). It is running again with debug info disabled; profile overrides are local-only and change no repository file.
- `protoc` was not present; `protoc` 29.3 was installed locally from the official release archive whose SHA-256 matches the value pinned in `ci.yml`.
- `THE_BUDLUM_DIREKTIF.md` is intentionally absent from the repository (Bölüm 0.5: the document does not enter the repo; `tree_is_english`). Its absence is not a finding; the inventory is reconciled through `audit-notes/testnet/index.md`.
- All 1390+ Strix review threads repo-wide remain `resolved` in the ledger; the required `Strix Security Review` status is still unsatisfiable because Strix reports its included review quota exhausted. Branch protection was not bypassed, and no review comment was deleted.
- Newly opened: PR #201 `fix(storage): make the Merkle envelope requirement follow the VerifyMerkle gate` (base `budlum-stack`) closes B-0054. B-0049 repair (the test-fixture mutation) is prepared in a local worktree and will be pushed to `garden` once the focused regression passes locally; the production parser is unchanged.

## Local evidence and outstanding work

- The Garden staged tree passed formatting, the 16 `garden::net::tests` cases, the three-node validator/sentry/public relay test, and the no-bare-lock regression. The exact default library listing contained 6,038 tests.
- A complete default library test run is in progress. Passing targeted tests is not equivalent to a green full CI run.
- An Ubuntu Base userland run on the Debian host kernel found six swarm-start failures when the root filesystem had an empty resolver configuration. A valid-resolver rerun and full Ubuntu user journey remain outstanding; see B-0044 and the Ubuntu execution record.
- Other operating systems, the complete repository review, all-features tests, full CI/security runs and independent review remain outstanding.
- Source review of the consensus source revision `7533b71b` found that the domain plugin layer `src/main.rs:1502-1517` registers is never consulted: `DomainPluginRegistry::get`, `validate_domain_block` and `extract_commitment` have no non-test caller, so only the finality adapters constrain a foreign domain. See B-0046, and B-0047 for why the dead-API ratchet cannot see it.
- Source review of the consensus source revision `7533b71b` found that the PoSpace engine cannot register a plot outside test builds, so a domain of that kind can neither produce nor validate a block, and that its fork-choice weight comes from an unauthenticated witness field. See B-0045. This is a source-level finding with no reproduction harness of its own. Both source findings are recorded against `7533b71b`; whether they still hold on the later head `365e02f297eb` is unverified.
- The Garden frame budget has an additional lifetime issue documented as B-0043. An experimental fix exists locally but is not yet project-tested, committed or CI-verified.
- No new suppressions, ignored tests, forced pushes, protection bypasses or license changes are claimed in this snapshot.
- Third-party assessment, Strix approval, network-level load tests and the current status of privileged badge-token exposure remain open checks.
- B-0048 is fixed in `834ee878` on `agg/phase-5-pcs-claims`. Four targeted tests pass on that tree and two fail when the defect is restored, so the fix is measured. The full library run that turns the three red jobs green has not completed on that head, so the finding is fixed in code and not yet proven by CI.

## Additional Garden execution evidence

This is a later local snapshot. It does not turn any queued check in the historical table above into a success.

- Actual Garden source `3467a0ba` passes 18 separate-process scenario tests and the separate real-NAT test locally, 19/19 in total. The original Garden library run instead fails 1 of 118 cases, demonstrating why the integration result alone is not a completion claim.
- B-0049 / BLG-268 identifies the invalid short-chain test fixture. Local test-only commit `c1e9dfda1e7d4c87041b7272c0e7216c3cf9fe94` passes the focused regression and 118/118 Garden library cases. It is not yet pushed at this snapshot. Production invite checks are unchanged; the final-source scenario and CI remain pending.
- The original Garden source is also executed in checksum-verified Ubuntu Base 24.04.5 amd64 userland as UID 1000. The same Debian-built executable produces 8 passes and 6 failures with no resolver, then 14/14 passes with a valid resolver. This reproduces B-0044 on the actual lower branch, without pretending that it is an Ubuntu-native build or a separate Ubuntu kernel.
- B-0050 / BLG-269 records that the Garden store still retains complete raw content under the old id instead of using the canonical B.U.D. 3.0 pipeline. `main` lacks the required `src/storage/bud3/` dependency. Only that integration is stopped under the main-only rule; independent transport tests and audit work continue.
- B-0041 and B-0042 code is verified present on `budlum-stack` but absent from the checked Garden head. A staged or upper-branch fix is not a lower-branch closure. B-0043's completed-frame lifetime issue remains open.
- The supplied 1,063-file plan is reconciled against the 1,819-file newer inventory: 1,005 paths remain and 58 absent paths are retained in the migration/removal checklist. All 11 requested operating-system targets remain in the plan. None is marked complete based only on these partial runs.
- These changes introduce no suppressions, ignored tests, dependency pins, license changes, force-pushes or protection bypasses. No Strix comment is deleted or closed by this local evidence.
- B-0054 is fixed in PR #201 at `02de7030` on `fix/verify-merkle-gate`. `open_deal` required a Merkle envelope while every profile set `verify_merkle = false`, so a client that followed the profile was refused with `MerkleProofRequired`. Three tests pin the fix and the negative control reproduces the refusal exactly. CI run number pending.
