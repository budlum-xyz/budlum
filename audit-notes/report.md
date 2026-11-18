# Budlum audit report

GitHub snapshot: `2026-11-18T08:20:11.851162+00:00`. Counts refer to check runs returned for each recorded head, not a claim that every required workflow passed.
The branch heads and check results can change. Refresh before every push or merge.

## Live snapshot

| PR | Head to base | Head SHA | Check-run summary | Unresolved threads | Strix approval | Merge state |
|---|---|---|---|---|---|---|
| [#126](https://github.com/budlum-xyz/budlum/pull/126) | `testnet` to `main` | `6f18b67ff93e` | 73 success; 63 queued; 9 running; 0 failed | 0 | no approval found | blocked |
| [#164](https://github.com/budlum-xyz/budlum/pull/164) | `garden` to `testnet` | `c34cc016cf15` | 42 success; 61 queued; 5 running; 0 failed | 0 | no approval found | blocked |
| [#183](https://github.com/budlum-xyz/budlum/pull/183) | `budlum-stack` to `garden` | `fafae3e493c5` | 0 success; 98 queued; 0 running; 0 failed | 0 | no approval found | blocked |
| [#194](https://github.com/budlum-xyz/budlum/pull/194) | `budlum-consensus-of-consensuses` to `budlum-stack` | `f8bb8173ea59` | 23 success; 79 queued; 3 running; 0 failed | 0 | no approval found | dirty |
| [#198](https://github.com/budlum-xyz/budlum/pull/198) | `agg/phase-5-pcs-claims` to `budlum-consensus-of-consensuses` | `f45cd034d486` | 18 success; 81 queued; 3 running; 0 failed | 0 | no approval found | unstable |

The `main` branch protection API lists `Strix Security Review` as a required status. Strix reports that the included review quota is exhausted. This is an external blocker; do not bypass branch protection.
A changes-requested review from CodeRabbit remains in the review history of #164, #183 and #194. See the follow-up record.

## Records

- [Plan and full file inventory](plan.md)
- [Strix review ledger](strix-ledger.md)
- [Garden network findings B-0041 through B-0043](findings/garden-network.md)
- [Garden resolver finding B-0044](findings/garden-dns.md)
- [PoSpace engine finding B-0045](findings/pospace.md)
- [Review summary follow-up](findings/review-summaries.md)
- [Debian execution record](findings/os-debian.md)
- [Ubuntu userland execution record](findings/os-ubuntu.md)
- [Testnet specification index](testnet/index.md)

## Local evidence and outstanding work

- The Garden staged tree passed formatting, the 16 `garden::net::tests` cases, the three-node validator/sentry/public relay test, and the no-bare-lock regression. The exact default library listing contained 6,038 tests.
- A complete default library test run is in progress. Passing targeted tests is not equivalent to a green full CI run.
- An Ubuntu Base userland run on the Debian host kernel found six swarm-start failures when the root filesystem had an empty resolver configuration. A valid-resolver rerun and full Ubuntu user journey remain outstanding; see B-0044 and the Ubuntu execution record.
- Other operating systems, the complete repository review, all-features tests, full CI/security runs and independent review remain outstanding.
- Source review of the consensus head `7533b71b` found that the PoSpace engine cannot register a plot outside test builds, so a domain of that kind can neither produce nor validate a block, and that its fork-choice weight comes from an unauthenticated witness field. See B-0045. This is a source-level finding with no reproduction harness of its own.
- The Garden frame budget has an additional lifetime issue documented as B-0043. An experimental fix exists locally but is not yet project-tested, committed or CI-verified.
- No new suppressions, ignored tests, forced pushes, protection bypasses or license changes are claimed in this snapshot.
- Third-party assessment, Strix approval, network-level load tests and the current status of privileged badge-token exposure remain open checks.
