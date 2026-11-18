# Budlum audit report

GitHub snapshot: `2026-11-18T11:06Z`. Counts refer to check runs returned for each recorded head, not a claim that every required workflow passed. A queued run is not a passing run, so no row below is evidence of a green build.
The branch heads and check results can change. Refresh before every push or merge.

## Live snapshot

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
- [Garden invite regression, B-0049 / BLG-268](findings/garden-invite.md)
- [Garden B.U.D. 3.0 integration gap, B-0050 / BLG-269](findings/garden-storage.md)
- [Garden acceptance step evidence](testnet/garden-acceptance.md)
- [Garden main-only dependency stop report and design](testnet/garden-main-only.md)
- [Supplied inventory reconciliation](testnet/inventory-drift.md)
- [Review summary follow-up](findings/review-summaries.md)
- [Debian execution record](findings/os-debian.md)
- [Ubuntu userland execution record](findings/os-ubuntu.md)
- [Testnet specification index](testnet/index.md)

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
