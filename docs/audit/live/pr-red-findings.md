# Open-PR red-check findings

Snapshot: **2026-11-07 (Europe/Istanbul)**. This ledger records the checks reported by GitHub for every PR that was open when the inventory was collected. It is a finding inventory, not a claim that the integration branch is green.

## Counting and evidence rules

- **146 `FAILURE` check instances across 25 PRs are tracked below as open findings.** Each `PR-RED-nnn` ID identifies one source-head/check instance; repeated instances can share one root cause and are not represented as 146 independent defects.
- **868 `CANCELLED` instances and 2,545 pending/unconcluded instances are not called hard-red failures.** They remain validation gaps and are summarized separately. A cancelled or queued job is not successful evidence.
- A source-head failure is not automatically proof that the same defect exists at the integration head. Triage must read the log, map the failure to current code, and record a fixing commit plus executed evidence before the finding can close.
- Closing or integrating a source PR does not close its red finding. In particular, #101 and #103 were integrated after this snapshot; their failures remain open until their root causes are addressed or shown inapplicable with evidence.
- No Rust compilation, Rust test, green CI, mobile build, Docker rehearsal or testnet success is inferred from this static inventory.

## Failure counts by source PR

| Source PR | Hard-red instances | Cancelled instances | Pending/unconcluded |
| --- | ---: | ---: | ---: |
| #77 | 1 | 43 | 55 |
| #78 | 1 | 4 | 53 |
| #79 | 1 | 43 | 55 |
| #80 | 6 | 35 | 55 |
| #81 | 3 | 41 | 55 |
| #82 | 2 | 40 | 56 |
| #84 | 5 | 34 | 56 |
| #86 | 7 | 31 | 55 |
| #92 | 2 | 39 | 55 |
| #93 | 7 | 32 | 55 |
| #94 | 8 | 33 | 55 |
| #95 | 8 | 33 | 55 |
| #96 | 26 | 11 | 56 |
| #98 | 3 | 93 | 1 |
| #99 | 1 | 55 | 1 |
| #100 | 11 | 25 | 55 |
| #101 | 28 | 21 | 2 |
| #102 | 2 | 0 | 54 |
| #103 | 8 | 32 | 1 |
| #104 | 3 | 38 | 55 |
| #107 | 4 | 37 | 56 |
| #109 | 6 | 88 | 2 |
| #121 | 1 | 0 | 48 |
| #136 | 1 | 0 | 48 |
| #148 | 1 | 0 | 49 |

## Root-cause triage queue

These groups deduplicate the work by check name only. They are not yet root-cause conclusions; logs still have to establish which groups share a defect.

| Failed check | Instances | Triage state |
| --- | ---: | --- |
| Cross-Platform Digest (windows-latest) (item 2) | 15 | UNTRIAGED |
| Cross-arch determinism (ubuntu-24.04) | 12 | UNTRIAGED |
| Cross-arch determinism (ubuntu-24.04-arm) | 10 | UNTRIAGED |
| Dependency Review (GH Advisory, PR diff) | 10 | UNTRIAGED |
| Stage 1 (pinned) | 9 | UNTRIAGED |
| OSV Scanner (OSV.dev = RustSec + GHSA + NVD) | 7 | UNTRIAGED |
| Stage 1 (independent) | 7 | UNTRIAGED |
| Audit Guard (fail-closed review boundary) | 5 | UNTRIAGED |
| Cargo Vet (supply-chain trust, ratchet) | 5 | UNTRIAGED |
| Devnet Multi-Node Smoke (4x PoS mesh + metrics + operator-RPC izolasyon) | 5 | UNTRIAGED |
| Semver Check (item 5: public API breakage gate) | 5 | UNTRIAGED |
| Semgrep (p/rust + p/security-audit + p/secrets) | 4 | UNTRIAGED |
| Typos (spell check, calibrated) | 4 | UNTRIAGED |
| docker-smoke | 4 | UNTRIAGED |
| CodeQL (Rust SAST) | 3 | UNTRIAGED |
| Cross-Platform Digest (macos-latest) (item 2) | 3 | UNTRIAGED |
| build-and-unit-tests | 3 | UNTRIAGED |
| iOS kit tests and Rust parity | 3 | UNTRIAGED |
| Auditable + Audit (binary SBOM + CVE) | 2 | UNTRIAGED |
| Binary Size (rapor) | 2 | UNTRIAGED |
| Economy Invariants | 2 | UNTRIAGED |
| Geiger: unsafe visibility (the first-party 0 evidence layer) | 2 | UNTRIAGED |
| MSRV check (1.97.1) | 2 | UNTRIAGED |
| Repo Lint (actionlint + buf + genesis + zizmor) | 2 | UNTRIAGED |
| Software token with PKCS#11 3.2 (kryoptic) | 2 | UNTRIAGED |
| device-log-analyzer | 2 | UNTRIAGED |
| AddressSanitizer + debug std (in place of careful) | 1 | UNTRIAGED |
| Benchmark Regression (item 10) | 1 | UNTRIAGED |
| BudZero / BudZKVM | 1 | UNTRIAGED |
| Budlum Core PQ build | 1 | UNTRIAGED |
| Budlum Core library test | 1 | UNTRIAGED |
| Cargo Deny (fuzz) | 1 | UNTRIAGED |
| Cargo Deny (root) | 1 | UNTRIAGED |
| Clippy drift (next stable toolchain) | 1 | UNTRIAGED |
| Coverage (nextest + llvm-cov, ratchet) | 1 | UNTRIAGED |
| Miri UB Inspection (crypto + budzero, nightly-2026-07-19) (item 4) | 1 | UNTRIAGED |
| Network Hardening | 1 | UNTRIAGED |
| Secret Scan (gitleaks, full history) | 1 | UNTRIAGED |
| Serialize Map Keys Are Strings | 1 | UNTRIAGED |
| Storage provider gate | 1 | UNTRIAGED |
| Udeps: the unused dependency gate | 1 | UNTRIAGED |
| cargo-hack feature matrix | 1 | UNTRIAGED |

## Triage log

| Findings | Executed triage | Current disposition |
| --- | --- | --- |
| PR-RED-121, PR-RED-122 | GitHub job metadata for source head `d87acf7b621f` shows `Build` succeeded and `Canonical digests` failed in both Stage 1 jobs. Raw log download redirected to the unavailable `results-receiver.actions.githubusercontent.com` host, so no compiler/test/digest line is asserted. The #102 ceremony regressions run separately and do not prove canonical digest parity. | OPEN — digest failure is located to a step, but its root cause and current-tree mapping remain unproven. |

## Hard-red finding register

| Finding | Source PR | Source head | Failed check | State |
| --- | ---: | --- | --- | --- |
| PR-RED-001 | #77 | `3c8a45fb182b` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42241897794/job/127974040174) | OPEN — log triage required |
| PR-RED-002 | #78 | `8cb10107585e` | [Stage 1 (independent)](https://github.com/lubothebook/budlum/actions/runs/42198889256/job/127828955673) | OPEN — log triage required |
| PR-RED-003 | #79 | `130aacd8a2ed` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42199012518/job/127829369755) | OPEN — log triage required |
| PR-RED-004 | #80 | `bfe2876f57de` | [Cross-Platform Digest (macos-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42241521751/job/127972741280) | OPEN — log triage required |
| PR-RED-005 | #80 | `bfe2876f57de` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42241521751/job/127972741567) | OPEN — log triage required |
| PR-RED-006 | #80 | `bfe2876f57de` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42241521599/job/127972738605) | OPEN — log triage required |
| PR-RED-007 | #80 | `bfe2876f57de` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42241521599/job/127972738481) | OPEN — log triage required |
| PR-RED-008 | #80 | `bfe2876f57de` | [OSV Scanner (OSV.dev = RustSec + GHSA + NVD)](https://github.com/lubothebook/budlum/actions/runs/42241521560/job/127972734032) | OPEN — log triage required |
| PR-RED-009 | #80 | `bfe2876f57de` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42241521539/job/127972736868) | OPEN — log triage required |
| PR-RED-010 | #81 | `e8f7365bf48b` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42198974587/job/127829253606) | OPEN — log triage required |
| PR-RED-011 | #81 | `e8f7365bf48b` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42198974935/job/127829250843) | OPEN — log triage required |
| PR-RED-012 | #81 | `e8f7365bf48b` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42198974982/job/127829250455) | OPEN — log triage required |
| PR-RED-013 | #82 | `5685e03d87c2` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42198958428/job/127829195348) | OPEN — log triage required |
| PR-RED-014 | #82 | `5685e03d87c2` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42198958681/job/127829195487) | OPEN — log triage required |
| PR-RED-015 | #84 | `f072940b08ad` | [Audit Guard (fail-closed review boundary)](https://github.com/lubothebook/budlum/actions/runs/42245686648/job/127987182455) | OPEN — log triage required |
| PR-RED-016 | #84 | `f072940b08ad` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42245686509/job/127987184030) | OPEN — log triage required |
| PR-RED-017 | #84 | `f072940b08ad` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42245686885/job/127987183946) | OPEN — log triage required |
| PR-RED-018 | #84 | `f072940b08ad` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42245686516/job/127987180717) | OPEN — log triage required |
| PR-RED-019 | #84 | `f072940b08ad` | [Devnet Multi-Node Smoke (4x PoS mesh + metrics + operator-RPC izolasyon)](https://github.com/lubothebook/budlum/actions/runs/42245686515/job/127987180820) | OPEN — log triage required |
| PR-RED-020 | #86 | `b2ba0fdb4bd7` | [Audit Guard (fail-closed review boundary)](https://github.com/lubothebook/budlum/actions/runs/42203623000/job/127844704755) | OPEN — log triage required |
| PR-RED-021 | #86 | `b2ba0fdb4bd7` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42203623080/job/127844709301) | OPEN — log triage required |
| PR-RED-022 | #86 | `b2ba0fdb4bd7` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42203623080/job/127844709176) | OPEN — log triage required |
| PR-RED-023 | #86 | `b2ba0fdb4bd7` | [OSV Scanner (OSV.dev = RustSec + GHSA + NVD)](https://github.com/lubothebook/budlum/actions/runs/42203622896/job/127844705416) | OPEN — log triage required |
| PR-RED-024 | #86 | `b2ba0fdb4bd7` | [Semgrep (p/rust + p/security-audit + p/secrets)](https://github.com/lubothebook/budlum/actions/runs/42203622907/job/127844704559) | OPEN — log triage required |
| PR-RED-025 | #86 | `b2ba0fdb4bd7` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42203623148/job/127844706455) | OPEN — log triage required |
| PR-RED-026 | #86 | `b2ba0fdb4bd7` | [docker-smoke](https://github.com/lubothebook/budlum/actions/runs/42203622996/job/127844705771) | OPEN — log triage required |
| PR-RED-027 | #92 | `9d532a8a1a02` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42205204463/job/127849980012) | OPEN — log triage required |
| PR-RED-028 | #92 | `9d532a8a1a02` | [build-and-unit-tests](https://github.com/lubothebook/budlum/actions/runs/42205204506/job/127849972187) | OPEN — log triage required |
| PR-RED-029 | #93 | `806201bbb36c` | [Binary Size (rapor)](https://github.com/lubothebook/budlum/actions/runs/42206265175/job/127853567341) | OPEN — log triage required |
| PR-RED-030 | #93 | `806201bbb36c` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42206265216/job/127853570090) | OPEN — log triage required |
| PR-RED-031 | #93 | `806201bbb36c` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42206265041/job/127853568504) | OPEN — log triage required |
| PR-RED-032 | #93 | `806201bbb36c` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42206265041/job/127853568400) | OPEN — log triage required |
| PR-RED-033 | #93 | `806201bbb36c` | [OSV Scanner (OSV.dev = RustSec + GHSA + NVD)](https://github.com/lubothebook/budlum/actions/runs/42206265340/job/127853567579) | OPEN — log triage required |
| PR-RED-034 | #93 | `806201bbb36c` | [Semgrep (p/rust + p/security-audit + p/secrets)](https://github.com/lubothebook/budlum/actions/runs/42206265330/job/127853568263) | OPEN — log triage required |
| PR-RED-035 | #93 | `806201bbb36c` | [Semver Check (item 5: public API breakage gate)](https://github.com/lubothebook/budlum/actions/runs/42206265401/job/127853568485) | OPEN — log triage required |
| PR-RED-036 | #94 | `7bf2d223b451` | [Cargo Vet (supply-chain trust, ratchet)](https://github.com/lubothebook/budlum/actions/runs/42241104140/job/127971304763) | OPEN — log triage required |
| PR-RED-037 | #94 | `7bf2d223b451` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42241104172/job/127971313266) | OPEN — log triage required |
| PR-RED-038 | #94 | `7bf2d223b451` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42241104142/job/127971307742) | OPEN — log triage required |
| PR-RED-039 | #94 | `7bf2d223b451` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42241104142/job/127971307976) | OPEN — log triage required |
| PR-RED-040 | #94 | `7bf2d223b451` | [OSV Scanner (OSV.dev = RustSec + GHSA + NVD)](https://github.com/lubothebook/budlum/actions/runs/42241104101/job/127971305023) | OPEN — log triage required |
| PR-RED-041 | #94 | `7bf2d223b451` | [Semgrep (p/rust + p/security-audit + p/secrets)](https://github.com/lubothebook/budlum/actions/runs/42241104211/job/127971304313) | OPEN — log triage required |
| PR-RED-042 | #94 | `7bf2d223b451` | [Stage 1 (independent)](https://github.com/lubothebook/budlum/actions/runs/42241104072/job/127971325036) | OPEN — log triage required |
| PR-RED-043 | #94 | `7bf2d223b451` | [Typos (spell check, calibrated)](https://github.com/lubothebook/budlum/actions/runs/42241104074/job/127971304099) | OPEN — log triage required |
| PR-RED-044 | #95 | `f17b9c0101ed` | [Cross-Platform Digest (macos-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42208073830/job/127859600704) | OPEN — log triage required |
| PR-RED-045 | #95 | `f17b9c0101ed` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42208073830/job/127859600675) | OPEN — log triage required |
| PR-RED-046 | #95 | `f17b9c0101ed` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42208073909/job/127859597996) | OPEN — log triage required |
| PR-RED-047 | #95 | `f17b9c0101ed` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42208073909/job/127859598208) | OPEN — log triage required |
| PR-RED-048 | #95 | `f17b9c0101ed` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42208073989/job/127859595348) | OPEN — log triage required |
| PR-RED-049 | #95 | `f17b9c0101ed` | [Geiger: unsafe visibility (the first-party 0 evidence layer)](https://github.com/lubothebook/budlum/actions/runs/42208073940/job/127859593715) | OPEN — log triage required |
| PR-RED-050 | #95 | `f17b9c0101ed` | [Software token with PKCS#11 3.2 (kryoptic)](https://github.com/lubothebook/budlum/actions/runs/42208073889/job/127859593975) | OPEN — log triage required |
| PR-RED-051 | #95 | `f17b9c0101ed` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42208073844/job/127859594646) | OPEN — log triage required |
| PR-RED-052 | #96 | `329e9bab0fa2` | [AddressSanitizer + debug std (in place of careful)](https://github.com/lubothebook/budlum/actions/runs/42240005602/job/127967479208) | OPEN — log triage required |
| PR-RED-053 | #96 | `329e9bab0fa2` | [Audit Guard (fail-closed review boundary)](https://github.com/lubothebook/budlum/actions/runs/42240006592/job/127967486211) | OPEN — log triage required |
| PR-RED-054 | #96 | `329e9bab0fa2` | [Auditable + Audit (binary SBOM + CVE)](https://github.com/lubothebook/budlum/actions/runs/42240005924/job/127967486183) | OPEN — log triage required |
| PR-RED-055 | #96 | `329e9bab0fa2` | [Benchmark Regression (item 10)](https://github.com/lubothebook/budlum/actions/runs/42240005755/job/127967482086) | OPEN — log triage required |
| PR-RED-056 | #96 | `329e9bab0fa2` | [Cargo Vet (supply-chain trust, ratchet)](https://github.com/lubothebook/budlum/actions/runs/42240006069/job/127967482580) | OPEN — log triage required |
| PR-RED-057 | #96 | `329e9bab0fa2` | [CodeQL (Rust SAST)](https://github.com/lubothebook/budlum/actions/runs/42240005699/job/127967484975) | OPEN — log triage required |
| PR-RED-058 | #96 | `329e9bab0fa2` | [Cross-Platform Digest (macos-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42240005850/job/127967490171) | OPEN — log triage required |
| PR-RED-059 | #96 | `329e9bab0fa2` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42240005850/job/127967489449) | OPEN — log triage required |
| PR-RED-060 | #96 | `329e9bab0fa2` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42240005699/job/127967485167) | OPEN — log triage required |
| PR-RED-061 | #96 | `329e9bab0fa2` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42240005699/job/127967484572) | OPEN — log triage required |
| PR-RED-062 | #96 | `329e9bab0fa2` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42240006142/job/127967484266) | OPEN — log triage required |
| PR-RED-063 | #96 | `329e9bab0fa2` | [Devnet Multi-Node Smoke (4x PoS mesh + metrics + operator-RPC izolasyon)](https://github.com/lubothebook/budlum/actions/runs/42240005777/job/127967485016) | OPEN — log triage required |
| PR-RED-064 | #96 | `329e9bab0fa2` | [Geiger: unsafe visibility (the first-party 0 evidence layer)](https://github.com/lubothebook/budlum/actions/runs/42240006227/job/127967515861) | OPEN — log triage required |
| PR-RED-065 | #96 | `329e9bab0fa2` | [Miri UB Inspection (crypto + budzero, nightly-2026-07-19) (item 4)](https://github.com/lubothebook/budlum/actions/runs/42240005602/job/127967479583) | OPEN — log triage required |
| PR-RED-066 | #96 | `329e9bab0fa2` | [OSV Scanner (OSV.dev = RustSec + GHSA + NVD)](https://github.com/lubothebook/budlum/actions/runs/42240005851/job/127967481334) | OPEN — log triage required |
| PR-RED-067 | #96 | `329e9bab0fa2` | [Semver Check (item 5: public API breakage gate)](https://github.com/lubothebook/budlum/actions/runs/42240005824/job/127967482817) | OPEN — log triage required |
| PR-RED-068 | #96 | `329e9bab0fa2` | [Software token with PKCS#11 3.2 (kryoptic)](https://github.com/lubothebook/budlum/actions/runs/42240006056/job/127967483334) | OPEN — log triage required |
| PR-RED-069 | #96 | `329e9bab0fa2` | [Stage 1 (independent)](https://github.com/lubothebook/budlum/actions/runs/42240006095/job/127967483024) | OPEN — log triage required |
| PR-RED-070 | #96 | `329e9bab0fa2` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42240006095/job/127967482677) | OPEN — log triage required |
| PR-RED-071 | #96 | `329e9bab0fa2` | [Typos (spell check, calibrated)](https://github.com/lubothebook/budlum/actions/runs/42240005606/job/127967480638) | OPEN — log triage required |
| PR-RED-072 | #96 | `329e9bab0fa2` | [Udeps: the unused dependency gate](https://github.com/lubothebook/budlum/actions/runs/42240006227/job/127967516419) | OPEN — log triage required |
| PR-RED-073 | #96 | `329e9bab0fa2` | [build-and-unit-tests](https://github.com/lubothebook/budlum/actions/runs/42239993984/job/127967431842) | OPEN — log triage required |
| PR-RED-074 | #96 | `329e9bab0fa2` | [build-and-unit-tests](https://github.com/lubothebook/budlum/actions/runs/42240005834/job/127967475062) | OPEN — log triage required |
| PR-RED-075 | #96 | `329e9bab0fa2` | [device-log-analyzer](https://github.com/lubothebook/budlum/actions/runs/42239993984/job/127967432332) | OPEN — log triage required |
| PR-RED-076 | #96 | `329e9bab0fa2` | [device-log-analyzer](https://github.com/lubothebook/budlum/actions/runs/42240005834/job/127967474893) | OPEN — log triage required |
| PR-RED-077 | #96 | `329e9bab0fa2` | [docker-smoke](https://github.com/lubothebook/budlum/actions/runs/42240005777/job/127967484673) | OPEN — log triage required |
| PR-RED-078 | #98 | `b4e568a7e10f` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42206563848/job/127854588372) | OPEN — log triage required |
| PR-RED-079 | #98 | `b4e568a7e10f` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42206563913/job/127854588300) | OPEN — log triage required |
| PR-RED-080 | #98 | `b4e568a7e10f` | [Devnet Multi-Node Smoke (4x PoS mesh + metrics + operator-RPC izolasyon)](https://github.com/lubothebook/budlum/actions/runs/42206563925/job/127854588409) | OPEN — log triage required |
| PR-RED-081 | #99 | `37e44aa14a22` | [Stage 1 (independent)](https://github.com/lubothebook/budlum/actions/runs/42208062312/job/127859551152) | OPEN — log triage required |
| PR-RED-082 | #100 | `55b887f2914d` | [Cargo Vet (supply-chain trust, ratchet)](https://github.com/lubothebook/budlum/actions/runs/42210254903/job/127866840069) | OPEN — log triage required |
| PR-RED-083 | #100 | `55b887f2914d` | [CodeQL (Rust SAST)](https://github.com/lubothebook/budlum/actions/runs/42210254898/job/127866841153) | OPEN — log triage required |
| PR-RED-084 | #100 | `55b887f2914d` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42210255076/job/127866846793) | OPEN — log triage required |
| PR-RED-085 | #100 | `55b887f2914d` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42210254898/job/127866841448) | OPEN — log triage required |
| PR-RED-086 | #100 | `55b887f2914d` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42210254898/job/127866841385) | OPEN — log triage required |
| PR-RED-087 | #100 | `55b887f2914d` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42210255075/job/127866840907) | OPEN — log triage required |
| PR-RED-088 | #100 | `55b887f2914d` | [OSV Scanner (OSV.dev = RustSec + GHSA + NVD)](https://github.com/lubothebook/budlum/actions/runs/42210255006/job/127866839251) | OPEN — log triage required |
| PR-RED-089 | #100 | `55b887f2914d` | [Semver Check (item 5: public API breakage gate)](https://github.com/lubothebook/budlum/actions/runs/42210254778/job/127866837592) | OPEN — log triage required |
| PR-RED-090 | #100 | `55b887f2914d` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42210254936/job/127866839697) | OPEN — log triage required |
| PR-RED-091 | #100 | `55b887f2914d` | [Typos (spell check, calibrated)](https://github.com/lubothebook/budlum/actions/runs/42210254784/job/127866838244) | OPEN — log triage required |
| PR-RED-092 | #100 | `55b887f2914d` | [docker-smoke](https://github.com/lubothebook/budlum/actions/runs/42210254844/job/127866839016) | OPEN — log triage required |
| PR-RED-093 | #101 | `da169ed9f86a` | [Audit Guard (fail-closed review boundary)](https://github.com/lubothebook/budlum/actions/runs/42237268166/job/127958044163) | OPEN — log triage required |
| PR-RED-094 | #101 | `da169ed9f86a` | [Auditable + Audit (binary SBOM + CVE)](https://github.com/lubothebook/budlum/actions/runs/42237268748/job/127958046907) | OPEN — log triage required |
| PR-RED-095 | #101 | `da169ed9f86a` | [Binary Size (rapor)](https://github.com/lubothebook/budlum/actions/runs/42237268748/job/127958046236) | OPEN — log triage required |
| PR-RED-096 | #101 | `da169ed9f86a` | [BudZero / BudZKVM](https://github.com/lubothebook/budlum/actions/runs/42237267965/job/127958045493) | OPEN — log triage required |
| PR-RED-097 | #101 | `da169ed9f86a` | [Budlum Core PQ build](https://github.com/lubothebook/budlum/actions/runs/42237267965/job/127958045009) | OPEN — log triage required |
| PR-RED-098 | #101 | `da169ed9f86a` | [Cargo Deny (root)](https://github.com/lubothebook/budlum/actions/runs/42237267965/job/127958045033) | OPEN — log triage required |
| PR-RED-099 | #101 | `da169ed9f86a` | [Cargo Vet (supply-chain trust, ratchet)](https://github.com/lubothebook/budlum/actions/runs/42237268219/job/127958050881) | OPEN — log triage required |
| PR-RED-100 | #101 | `da169ed9f86a` | [Clippy drift (next stable toolchain)](https://github.com/lubothebook/budlum/actions/runs/42237268335/job/127958045970) | OPEN — log triage required |
| PR-RED-101 | #101 | `da169ed9f86a` | [CodeQL (Rust SAST)](https://github.com/lubothebook/budlum/actions/runs/42237268281/job/127958045927) | OPEN — log triage required |
| PR-RED-102 | #101 | `da169ed9f86a` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42237268100/job/127958044518) | OPEN — log triage required |
| PR-RED-103 | #101 | `da169ed9f86a` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42237268281/job/127958046209) | OPEN — log triage required |
| PR-RED-104 | #101 | `da169ed9f86a` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42237268281/job/127958046531) | OPEN — log triage required |
| PR-RED-105 | #101 | `da169ed9f86a` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42237268381/job/127958045677) | OPEN — log triage required |
| PR-RED-106 | #101 | `da169ed9f86a` | [Devnet Multi-Node Smoke (4x PoS mesh + metrics + operator-RPC izolasyon)](https://github.com/lubothebook/budlum/actions/runs/42237268605/job/127958047161) | OPEN — log triage required |
| PR-RED-107 | #101 | `da169ed9f86a` | [Economy Invariants](https://github.com/lubothebook/budlum/actions/runs/42237267965/job/127958045130) | OPEN — log triage required |
| PR-RED-108 | #101 | `da169ed9f86a` | [MSRV check (1.97.1)](https://github.com/lubothebook/budlum/actions/runs/42237268281/job/127958046125) | OPEN — log triage required |
| PR-RED-109 | #101 | `da169ed9f86a` | [Network Hardening](https://github.com/lubothebook/budlum/actions/runs/42237267965/job/127958044830) | OPEN — log triage required |
| PR-RED-110 | #101 | `da169ed9f86a` | [OSV Scanner (OSV.dev = RustSec + GHSA + NVD)](https://github.com/lubothebook/budlum/actions/runs/42237267973/job/127958043968) | OPEN — log triage required |
| PR-RED-111 | #101 | `da169ed9f86a` | [Repo Lint (actionlint + buf + genesis + zizmor)](https://github.com/lubothebook/budlum/actions/runs/42237267965/job/127958045199) | OPEN — log triage required |
| PR-RED-112 | #101 | `da169ed9f86a` | [Semgrep (p/rust + p/security-audit + p/secrets)](https://github.com/lubothebook/budlum/actions/runs/42237268161/job/127958045607) | OPEN — log triage required |
| PR-RED-113 | #101 | `da169ed9f86a` | [Semver Check (item 5: public API breakage gate)](https://github.com/lubothebook/budlum/actions/runs/42237268489/job/127958046035) | OPEN — log triage required |
| PR-RED-114 | #101 | `da169ed9f86a` | [Serialize Map Keys Are Strings](https://github.com/lubothebook/budlum/actions/runs/42237267965/job/127958045118) | OPEN — log triage required |
| PR-RED-115 | #101 | `da169ed9f86a` | [Stage 1 (independent)](https://github.com/lubothebook/budlum/actions/runs/42237268316/job/127958046057) | OPEN — log triage required |
| PR-RED-116 | #101 | `da169ed9f86a` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42237268316/job/127958045527) | OPEN — log triage required |
| PR-RED-117 | #101 | `da169ed9f86a` | [Storage provider gate](https://github.com/lubothebook/budlum/actions/runs/42237267965/job/127958044897) | OPEN — log triage required |
| PR-RED-118 | #101 | `da169ed9f86a` | [Typos (spell check, calibrated)](https://github.com/lubothebook/budlum/actions/runs/42237268245/job/127958046387) | OPEN — log triage required |
| PR-RED-119 | #101 | `da169ed9f86a` | [cargo-hack feature matrix](https://github.com/lubothebook/budlum/actions/runs/42237268281/job/127958046252) | OPEN — log triage required |
| PR-RED-120 | #101 | `da169ed9f86a` | [docker-smoke](https://github.com/lubothebook/budlum/actions/runs/42237268605/job/127958046193) | OPEN — log triage required |
| PR-RED-121 | #102 | `d87acf7b621f` | [Stage 1 (independent)](https://github.com/lubothebook/budlum/actions/runs/42237865072/job/127960134751) | OPEN — Canonical digests failed; raw log unavailable |
| PR-RED-122 | #102 | `d87acf7b621f` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42237865072/job/127960135274) | OPEN — Canonical digests failed; raw log unavailable |
| PR-RED-123 | #103 | `26a7d4385c20` | [Budlum Core library test](https://github.com/lubothebook/budlum/actions/runs/42238560167/job/127962524799) | OPEN — log triage required |
| PR-RED-124 | #103 | `26a7d4385c20` | [Cargo Deny (fuzz)](https://github.com/lubothebook/budlum/actions/runs/42238560167/job/127962524878) | OPEN — log triage required |
| PR-RED-125 | #103 | `26a7d4385c20` | [Coverage (nextest + llvm-cov, ratchet)](https://github.com/lubothebook/budlum/actions/runs/42238560167/job/127962524566) | OPEN — log triage required |
| PR-RED-126 | #103 | `26a7d4385c20` | [Economy Invariants](https://github.com/lubothebook/budlum/actions/runs/42238560167/job/127962524542) | OPEN — log triage required |
| PR-RED-127 | #103 | `26a7d4385c20` | [Repo Lint (actionlint + buf + genesis + zizmor)](https://github.com/lubothebook/budlum/actions/runs/42238560167/job/127962524948) | OPEN — log triage required |
| PR-RED-128 | #103 | `26a7d4385c20` | [Secret Scan (gitleaks, full history)](https://github.com/lubothebook/budlum/actions/runs/42238560167/job/127962524619) | OPEN — log triage required |
| PR-RED-129 | #103 | `26a7d4385c20` | [Stage 1 (independent)](https://github.com/lubothebook/budlum/actions/runs/42238560403/job/127962522784) | OPEN — log triage required |
| PR-RED-130 | #103 | `26a7d4385c20` | [Stage 1 (pinned)](https://github.com/lubothebook/budlum/actions/runs/42238560403/job/127962522417) | OPEN — log triage required |
| PR-RED-131 | #104 | `86aecc0bb5f2` | [Audit Guard (fail-closed review boundary)](https://github.com/lubothebook/budlum/actions/runs/42242780600/job/127977076075) | OPEN — log triage required |
| PR-RED-132 | #104 | `86aecc0bb5f2` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42242780765/job/127977081347) | OPEN — log triage required |
| PR-RED-133 | #104 | `86aecc0bb5f2` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42242780688/job/127977077160) | OPEN — log triage required |
| PR-RED-134 | #107 | `cce88d0fbef2` | [Cargo Vet (supply-chain trust, ratchet)](https://github.com/lubothebook/budlum/actions/runs/42247615985/job/127993859033) | OPEN — log triage required |
| PR-RED-135 | #107 | `cce88d0fbef2` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42247615936/job/127993859958) | OPEN — log triage required |
| PR-RED-136 | #107 | `cce88d0fbef2` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42247616040/job/127993860695) | OPEN — log triage required |
| PR-RED-137 | #107 | `cce88d0fbef2` | [MSRV check (1.97.1)](https://github.com/lubothebook/budlum/actions/runs/42247616040/job/127993859836) | OPEN — log triage required |
| PR-RED-138 | #109 | `409548ca3379` | [Cross-Platform Digest (windows-latest) (item 2)](https://github.com/lubothebook/budlum/actions/runs/42246158028/job/127988796301) | OPEN — log triage required |
| PR-RED-139 | #109 | `409548ca3379` | [Cross-arch determinism (ubuntu-24.04)](https://github.com/lubothebook/budlum/actions/runs/42246158101/job/127988797239) | OPEN — log triage required |
| PR-RED-140 | #109 | `409548ca3379` | [Cross-arch determinism (ubuntu-24.04-arm)](https://github.com/lubothebook/budlum/actions/runs/42246158101/job/127988797376) | OPEN — log triage required |
| PR-RED-141 | #109 | `409548ca3379` | [Dependency Review (GH Advisory, PR diff)](https://github.com/lubothebook/budlum/actions/runs/42246158066/job/127988795955) | OPEN — log triage required |
| PR-RED-142 | #109 | `409548ca3379` | [Devnet Multi-Node Smoke (4x PoS mesh + metrics + operator-RPC izolasyon)](https://github.com/lubothebook/budlum/actions/runs/42246158104/job/127988795487) | OPEN — log triage required |
| PR-RED-143 | #109 | `409548ca3379` | [Semver Check (item 5: public API breakage gate)](https://github.com/lubothebook/budlum/actions/runs/42246158092/job/127988796042) | OPEN — log triage required |
| PR-RED-144 | #121 | `dabfabe948ef` | [iOS kit tests and Rust parity](https://github.com/lubothebook/budlum/actions/runs/42346612717/job/128325629171) | OPEN — log triage required |
| PR-RED-145 | #136 | `a062412efdb2` | [iOS kit tests and Rust parity](https://github.com/lubothebook/budlum/actions/runs/42355158515/job/128351538085) | OPEN — log triage required |
| PR-RED-146 | #148 | `dea3282ce98c` | [iOS kit tests and Rust parity](https://github.com/lubothebook/budlum/actions/runs/42373847708/job/128407308947) | OPEN — log triage required |

## Cancelled-check summary

Cancellation is tracked as missing validation, not mislabeled as a code failure. Counts below include only PRs with at least one cancelled instance.

| Source PR | Cancelled instances |
| --- | ---: |
| #77 | 43 |
| #78 | 4 |
| #79 | 43 |
| #80 | 35 |
| #81 | 41 |
| #82 | 40 |
| #84 | 34 |
| #85 | 4 |
| #86 | 31 |
| #88 | 4 |
| #91 | 5 |
| #92 | 39 |
| #93 | 32 |
| #94 | 33 |
| #95 | 33 |
| #96 | 11 |
| #97 | 7 |
| #98 | 93 |
| #99 | 55 |
| #100 | 25 |
| #101 | 21 |
| #103 | 32 |
| #104 | 38 |
| #106 | 40 |
| #107 | 37 |
| #109 | 88 |

## Pending/unconcluded-check summary

Pending, queued, requested and otherwise unconcluded checks are not counted as red and are not counted as passed.

| Source PR | Pending/unconcluded instances |
| --- | ---: |
| #77 | 55 |
| #78 | 53 |
| #79 | 55 |
| #80 | 55 |
| #81 | 55 |
| #82 | 56 |
| #84 | 56 |
| #85 | 54 |
| #86 | 55 |
| #88 | 54 |
| #91 | 67 |
| #92 | 55 |
| #93 | 55 |
| #94 | 55 |
| #95 | 55 |
| #96 | 56 |
| #97 | 53 |
| #98 | 1 |
| #99 | 1 |
| #100 | 55 |
| #101 | 2 |
| #102 | 54 |
| #103 | 1 |
| #104 | 55 |
| #106 | 55 |
| #107 | 56 |
| #109 | 2 |
| #113 | 4 |
| #119 | 44 |
| #120 | 99 |
| #121 | 48 |
| #122 | 99 |
| #126 | 44 |
| #127 | 5 |
| #128 | 44 |
| #129 | 44 |
| #130 | 45 |
| #131 | 45 |
| #132 | 44 |
| #135 | 44 |
| #136 | 48 |
| #137 | 48 |
| #139 | 44 |
| #140 | 52 |
| #144 | 44 |
| #145 | 99 |
| #148 | 49 |
| #150 | 49 |
| #152 | 44 |
| #156 | 44 |
| #158 | 100 |
| #159 | 44 |
| #166 | 45 |

## Closure requirement

A finding may move out of `OPEN` only with (1) the failed-job log or a precise explanation of why it is environment-only, (2) the mapping to the integration tree, (3) the fixing integration commit when code is changed, and (4) the validation actually executed. Merely merging the source head, closing its PR, restarting CI, or seeing a later queued check is insufficient.
