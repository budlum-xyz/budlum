# Live PR-stack audit — 2026-11-06

Scope: every open pull request on `lubothebook/budlum` at the time of the audit,
`main` (`cccf1da`), and this branch (`arena/e607c9b9-budlum`). Method: `gh pr list`,
`gh pr view` (bodies and file lists), `gh run list`, `gh run view`, `git show`,
and a tokenizer-checked read of the tree. No other branch was pushed, and no
other pull request was closed, merged or retargeted by this session.

Live inputs (reproduce with the same commands):

```
gh pr list --state open --limit 100 --json number,title,body,files
gh pr list --state closed --limit 30 --json number,title,mergedAt
gh run list --branch main --limit 40 --json conclusion,name
```

Numbers in this file are a snapshot. The stack moves daily; counts drift.

## 1. The live picture

- **63 open pull requests.** All name their work package(s). Every T-Launch
  package (WP-01..WP-48, WP-61) is claimed by at least one open pull request.
  No T-Expansion package is claimed (see §3).
- **209 files are touched by two or more open pull requests.** The ten files
  with the highest fan-in: `docs/work/PACKAGES.md` (25 PRs),
  `.github/workflows/ci.yml` (14), `xtask/gates/src/main.rs` (14),
  `src/tests/mod.rs` (13), `THE_BUDLUM_DIREKTIF.md` (13),
  `src/chain/blockchain.rs` (12), `docs/audit/FINDINGS.md` (11),
  `src/execution/executor.rs` (11), `src/rpc/server.rs` (9),
  `src/crypto/domain_tags.rs` (9).
- **`main` is red before any branch exists.** The two `CI` runs on `cccf1da`
  both fail with, among others, `Gates`, `Budlum Core PQ build`,
  `Budlum Core library test`, `Budlum Core quality` (Format and Clippy),
  `Network Hardening`, `Cargo Deny (root)` and `Cargo Deny (fuzz)`.
  `Security Audit`, `Determinism`, `Watchdog`, `Semver Check`, `Semgrep`,
  `OSV Scanner`, `Extra Tooling`, `Diverse Double Compiling`, `Cargo Vet`,
  `Audit Guard`, `Typos` and `Docker Smoke` also fail. Successes: `Solidity`,
  `PKCS#11 3.2`, `Grype`, `Provenance`, `Supply Chain Extra`, `Benchmark`,
  `Solidity`. The failing-step logs are not downloadable from this network
  (`results-receiver.actions.githubusercontent.com` returns EOF), so the red
  is recorded as job names only. Two consequences follow:
  1. A green run on any PR head is not, by itself, evidence the *feature*
     works — the base is red, so no signal is attributable to the branch.
  2. No merge in the open stack is verifiably green today. Treat every
     "ready to merge" claim as unverified until `main` itself is green.
- **CI queues without a runner for open PRs.** PR #65 and PR #59 record their
  checks as `queued`/`pending` with no runner picking them up. The failure
  mode is invisible: pending is not green and not red, and it blocks nothing
  but proves nothing either.
- **Rust is not installed in several session workspaces** (recorded in #18,
  #39, #45, #52, #65, #77). No test in the open stack has been executed
  locally anywhere; CI is the first executor of every test in this repository.
- **The merged history is collapsed.** `main` holds a single squashed
  "Add files via upload" commit (`cccf1da`); earlier merged PRs (#5
  "Consolidate open PRs...", #6 "The A0 codec register and the dedup index")
  are folded into it. Closed-unmerged PRs are #2..#33, mostly WP-00 stop
  reports recording blocked queues; #18 is duplicated by #35 and carried by
  #68; #8 is duplicated lineage after the accidental stack merge recorded in
  its body.

## 2. Work package coverage (live, this audit)

Claim map (`WP` → claiming PRs). "Range artifacts" such as `WP-01..WP-64`
are excluded:

| WP | PRs |
|---|---|
| WP-01 | 12, 14, 18, 34, 35, 39, 40, 41, 47, 48, 53, 63, 68 |
| WP-02 | 11, 12, 35, 41, 68 |
| WP-03 | 12, 16, 35, 41, 42, 54, 68, 77 |
| WP-04 | 12, 16, 18, 20, 30, 31, 35, 40, 41, 42, 47, 49, 50, 63, 68, 72, 77, 79 |
| WP-05 | 16, 20, 24, 31, 35, 41, 42, 50, 57, 68, 72, 81, 83 |
| WP-06 | 11, 14, 41, 50, 60, 68 |
| WP-07 | 11, 14, 47, 56, 57, 69, 71, 75 |
| WP-08 | 12, 31, 37, 39, 40, 52 |
| WP-09 | 38, 47, 54, 64, 77, 80 |
| WP-10 | 47, 56 |
| WP-11 | 44, 56, 82 |
| WP-12 | 9, 12, 14, 34, 41, 81, 82 |
| WP-13 | 12, 40, 45, 70 |
| WP-14 | 60 |
| WP-15 | 14, 48, 52 |
| WP-16 | 14, 34, 37, 39, 42, 52, 58, 73 |
| WP-17 | 60, 62, 66, 67, 68, 73 |
| WP-18 | 43, 47, 56, 57 |
| WP-19 | 45, 55, 56, 57 |
| WP-20 | 13, 34, 41, 52, 56, 57, 59 |
| WP-21 | 40, 56, 57, 65, 73 |
| WP-22 | 14, 45, 56 |
| WP-23 | 79 |
| WP-24 | 14, 34, 41, 56, 65 |
| WP-25 | 37, 39, 40, 45, 52, 56 |
| WP-26 | 24, 34, 36, 40, 52, 73, 83 |
| WP-27 | 24, 46, 51, 61, 72, 78, 79 |
| WP-28 | 24, 56, 72, 73, 76 |
| WP-29 | 24 |
| WP-30 | 24 |
| WP-31 | 51, 79, 83 |
| WP-32 | 79 |
| WP-33 | 24, 34, 79 |
| WP-34 | 46, 61 |
| WP-35 | 72, 79, 83 |
| WP-36 | 56, 79, 82 |
| WP-37 | 56, 79 |
| WP-38 | 79 |
| WP-39 | 43 |
| WP-40 | 50, 73 |
| WP-41 | 34, 42, 52, 58, 59, 73, 83 |
| WP-42 | 24, 29, 30, 31, 34, 35, 42, 51, 52, 58, 61, 63, 68, 74 |
| WP-43 | 14, 31, 35, 50, 51, 56, 68 |
| WP-44 | 14, 34, 41, 48, 60 |
| WP-45 | 29, 30, 43, 44, 49 |
| WP-46 | 56, 79 |
| WP-47 | 56, 79 |
| WP-48 | 79 |
| WP-49..WP-55, WP-58..WP-60, WP-62, WP-63, WP-64 | **none** |
| WP-56 | 43, 56 |
| WP-57 | 30, 43 |
| WP-61 | 34, 41, 42, 52, 53 |

T-Expansion (WP-49..WP-64) is wholly unclaimed. This branch opens the
T-Expansion line with the WP-55 core (live streaming); see §5.

## 3. Findings recorded by this audit (BLG-288..BLG-297)

`docs/audit/FINDINGS.md` does not exist on `main` and is created by eleven
open PRs (#13, #31, #35, #36, #41, #44, #48, #50, #68, #77, #80), so this
audit records its own findings here with the next free identities (BLG-288
and up; BLG-268..BLG-281 and BLG-287 are already used by the open stack, per
their bodies). The integrator should migrate these rows into
`docs/audit/FINDINGS.md` on merge; none of them is claimed closed.

| ID | Severity | Finding | State |
|---|---|---|---|
| BLG-288 | High | `THE_BUDLUM_DIREKTIF.md` is tracked in the tree (`git cat-file -e cccf1da:THE_BUDLUM_DIREKTIF.md` succeeds). Directive 0.1.5: the binding directive does not enter the repository; the tree is English. | **Closed by this PR** (tracked copy removed; 0.1.5 also done in #42, #63, #77, #78 — four conflicting removals to de-duplicate at integration). |
| BLG-289 | High | `docs/work/PACKAGES.md` does not exist on `main` and is touched by 25 open PRs. Every package status row written by WP-04 will conflict with 24 other editors. | Open. Needs one named integrator and an order. |
| BLG-290 | High | `docs/audit/FINDINGS.md` does not exist on `main` and is touched by 11 open PRs. Ledger rows collide on every integration. | Open. Same fix as BLG-289. |
| BLG-291 | Medium | The directive's shared-append list (15.3.4) does not cover high fan-in files the stack edits concurrently: `xtask/gates/src/main.rs` (14), `src/tests/mod.rs` (13), `src/chain/blockchain.rs` (12), `src/execution/executor.rs` (11), `src/rpc/server.rs` (9), `src/crypto/domain_tags.rs` is listed but contested by 9 PRs in practice. | Open. The list needs a revision or the stack needs a merge train. |
| BLG-292 | High | Two open PRs (#77, #80) carry the same `#38 -> #54 -> #64` worker-ABI correction checkpoint. #77 itself records that it is a superset of the observed checkpoint. Integrating both applies the corrections twice under different SHAs. | Open. De-duplicate at integration; neither closed by this session. |
| BLG-293 | High | `main` is red (2/2 `CI` runs), failing `Gates`, `PQ build`, `library test`, `quality` (fmt, clippy), `Network Hardening`, `Cargo Deny`, plus `Security Audit`, `Determinism`, `Watchdog`. Failing-step logs are not downloadable from this network. No PR in the stack can demonstrate red-to-green today. | Open. Fix `main` first, then integrate. |
| BLG-294 | Medium | No open PR claims any T-Expansion package (WP-49..WP-55, WP-58..WP-60, WP-62..WP-64). Directive 15.4 lets agents run T-Expansion before launch; leaving them unowned means nothing exists at M7 while the launch gate stalls on nothing. | Open; **WP-55 core opened by this PR**. |
| BLG-295 | Medium | `src/object_layer/` exists on `main` (14 files, 5417 lines) and delivers the UOL core partially: identities, registry and root, charters, `FungibleV1`/`UniqueV1`, final-phase `Arrive`/`Call`/`Offer`/`Accept`/`HomeCall`/`Depart`, `AuditCustody`, escape records and four family profiles. Header V9 (`object_layer_root`), the `bud_get*` RPC reads, the tentative phase, challenges, `RecordV1` and the Sepolia run are absent and unclaimed. | Open. Needs an owner; closest packages are WP-49 (unclaimed) and WP-64 (unclaimed). |
| BLG-296 | Medium | PR #13 discloses 1855 changed lines against the 1500 cap (directive 15.5.2), excluding 263 generated lines. The cap is silent everywhere else it is breached; nothing in CI enforces it. | Open. Enforcement belongs in WP-42. |
| BLG-297 | Low | The "52 open PRs" figure in PR #72 and PR #73 titles is stale: 63 PRs are open at this audit. The audit docs of those PRs drift the moment one more PR opens. | Open. Numbers in audit docs must come from live queries with timestamps. |

## 4. Residual work carried by the 63 open PRs

Quoted from each PR's own body (first matching "not done" line, else title).
This is what "continue the other PRs" means concretely: the stack admits, in
its own words, what is left.

| PR | Scope | Residual / not done (as stated) |
|---|---|---|
| 8 | codec register + dedup index (conf stack) | integration order with the consolidation stream |
| 9 | WP-12 committee seats / Instant Seat Handover | full finality wiring continues re-rooted in #81 |
| 11 | WP-06 persistence out of content storage | WP-06 follow-ups and wiring continue in #60 |
| 12 | WP-01/02/03 live verification ledgers | M0 stays open; see #68 |
| 13 | WP-20 placement / custody / repair gates | 1855 lines > 1500 cap, disclosed; T20/T21 pending CI |
| 14 | WP-44 testnet feature closures | WP-44 delivery 1/N |
| 16 | WP-03 lane C ledger + engine inventory | reported in a follow-up comment |
| 18 | WP-04 lane D live audit 1/N | Rust never executed; CI not awaited |
| 20 | WP-05 concept owners + owner gate | counter unchanged by this PR |
| 24 | WP-05/26/27/28/29/30/33/42 — UEL coordinator, BudZero, EVM, RPC, WASM | large multi-package PR; per-package status untracked |
| 29 | WP-42 required-nightly gate | carries #30 forward; open for reconciliation |
| 30 | WP-42 float gate + coverage gate | slice 1/3 |
| 31 | WP-05/42/08 concept map + gates + mobile duty lane | "Not done, and named so the next packet does not guess" |
| 34 | WP-61/16/41 RPC+crypto, genesis, faucet | continuation missing from #34 tracked in #52 |
| 35 | WP-04 lane D live verification + index | delivery 1/N |
| 36 | WP-26 Execution Coordinator / EE isolation 1/2 | 2/2 pending (WP-26 split across PRs) |
| 37 | WP-16 40/50/10 epoch shares 1/N | storage/repair/relay payouts not implemented; continued in #39, #52 |
| 38 | WP-09 handshake request id | corrective stacked in #54, #64, #77/#80 |
| 39 | WP-16 three-share pool | BLG-263 partially open |
| 40 | WP-08/25 mobile duty lane, storage fee | İP-21 not merged; fee follow-ups pending |
| 41 | WP-61 RPC/crypto finding locks | BLG-004/BLG-010/TEST-GAP-07 scope only |
| 42 | WP-42 directive out of tree + canary | overlaps #63/#77/#78; open for rebase |
| 43 | WP-45/39/18 privacy, AI/BPQS boundary | 1/N of each |
| 44 | WP-45 + WP-11 | remaining WP-45 slices 2/3 and 3/3; WP-11 jobs 2-9 |
| 45 | bud3 & validators (WP-25/19/22/13) | sealed/grants/fees slices only |
| 46 | WP-34 migration kit core | continued in #61 |
| 47 | WP-18 RFC 6330 / carousel ceilings | delivery 1/N |
| 48 | WP-15 P2P decode / IPv6 eclipse / routing | `main` is red; no green claim |
| 49 | WP-45 privacy/AI subgraph | remaining WP-45 scope in later PRs |
| 50 | WP-05 concept map, ownership, counter | counter lowering under owner gate |
| 51 | WP-43/31 README + placeholder gates + Solana envelope | 1/N of each |
| 52 | WP-16/41 continuation of #34/#39 | explicitly not done listed in body |
| 53 | WP-61 BLG-004/BLG-010/TEST-GAP-07 | coverage gate slice |
| 54 | WP-09 ABI version refusal | stacked on #38; remains open |
| 55 | WP-19 BOF-1 / two paths / video commitment | legacy file removal and T7 in follow-up |
| 56 | WP-10/28/47 wire contract, GoE gateway, core/storage review | execution evidence pending first run on head |
| 57 | WP-21 aggregation volume (T25) | 44 check runs all queued, no runner |
| 58 | WP-41 faucet / operations 1/N | BLG-030 faucet leg fixed in code, pending CI |
| 59 | WP-41/20 readiness + storage-health series | all checks pending; runner never picked up |
| 60 | WP-06/17/14/44 persistence + core packages | continuation of #11 |
| 61 | WP-34, 3/3 migration proofs | remaining: Sepolia e2e record; fuzz target lands in nightly |
| 62 | WP-17 failure-atomic block application 1/N | stacked on #60; closes nothing alone |
| 63 | WP-42 directive out + required_fee read | continuation #74 stacked |
| 64 | WP-09 no uncertain write retries | checkpoint of the #38→#54→#64 chain |
| 65 | WP-24 object replacement 1/3 | replacement/access_tiering T22 delivered |
| 66 | WP-17 overflowing transaction costs 2/N | amount+fee overflow only |
| 67 | WP-17 spendable-balance fee gates 2/N | continues #62; supply-path slice |
| 68 | WP-01..05 M0 ledgers + concept name map 1/2 | M0 incomplete; 2/2 owed |
| 69 | WP-07, 1/N no_legacy_storage gate | ContentRef temporary; continued in #71, #75 |
| 70 | WP-13 presence protocol / suspension | absence never slashes (V-4); arbitration with #40 |
| 71 | WP-07, 2/N legacy storage RPC surface removal | stacked on #69 |
| 72 | WP-28, 1/2 Ethereum JSON-RPC namespace | subscriptions pending; 2/2 pending |
| 73 | WP-40, 1/N budlum-explorer rename + 52-PR audit | WP-40 remainder open (pages, indexer events) |
| 74 | WP-42 required_fee regression guard | stacked on #63 |
| 75 | WP-07, 3/N finish legacy-storage removal | integrates #69+#71; WIP |
| 76 | WP-28 filter owner binding | Ethereum filter connection ownership |
| 77 | WP-04 + WP-09 reconcile + transport hardening | BLG-281..287 recorded open |
| 78 | directive out of tree | duplicate overlap with #42/#63/#77 |
| 79 | WP-35, 1/3 execution limits + BLG-280 | waits on unmerged engines (WP-27) |
| 80 | WP-09 worker ABI correction stack | superset of #38→#54→#64; BLG-281.. pending |
| 81 | WP-12, 1/N committee seats re-rooted on main | remaining WP-12 work unspecified in 1/N |
| 82 | WP-11, 2/N mobile duty engine | jobs 2-9 of WP-11 open |
| 83 | WP-31, 1/N Solana JSON-RPC namespace | subscriptions pending; 2/N owed |

## 5. T-Expansion: the unclaimed eleven

Directive 15.4, rule 4: T-Expansion packages may be run before launch; their
PRs simply do not merge before M7, and they activate by height. The live stack
claims none of the following. Effort levels and dependency notes:

| WP | Package | Depends on | Note |
|---|---|---|---|
| WP-49 | Evrensel Nesne Katmanı (UOL) | M7, WP-30, WP-34, WP-44 (partial UOL on `main`, BLG-295) | XL; nothing merged |
| WP-50 | Move (Sui) execution environment | WP-35 | new `execution/move-sui/` |
| WP-51 | Cairo execution environment | WP-35 | new `execution/cairo/` |
| WP-52 | SVM and Move pointers | WP-30, WP-31, WP-32 | pointer model only |
| WP-53 | NEAR WASM / PolkaVM / TVM / UTXO / Plutus | WP-35 | five separate workers |
| WP-54 | shared compression context, codecs, private dedup | WP-22, WP-24 | codec ids 6-26 |
| WP-55 | **Canlı yayın (live streaming)** | WP-21 | **core opened by this PR** |
| WP-58 | F-Droid reproducible Android build | WP-36 | no `mobile/` on `main` |
| WP-59 | parallel execution (deterministic scheduler) | WP-35 | `src/execution/coordinator/scheduler/` |
| WP-60 | BudZero recursion, RV32, precompiles, domain proofs | WP-56 | XL |
| WP-62 | UOL CosmWasm and Cosmos SDK family | WP-49, WP-29 | needs WP-49 |
| WP-63 | UOL SVM family | WP-49, WP-31 | needs WP-49 |
| WP-64 | UOL Move family | WP-49, WP-32 | needs WP-49 |

What this PR delivers for WP-55: the live stream core — time segments
(2 s default), the BOF-1 `bit1` segment object with the `prev_object` chain,
the ratioless send order (source frames first, then continuous repair frames),
viewer join with the two-segment latency budget, chain verification for light
clients, and the final-commitment-to-NFT binding record — plus the
`bud3_live_is_closed_on_testnet` gate (G-7) and the T13-shaped test
(`bud3_live_stream`). The optical send path (P1 profile) is a per-request
transport property, never written in the object; the StorageTx wiring is an
integration step shared with WP-21 and the activation height is set after M7.
The rest of WP-55 (the broadcast driver, the gateway door, measurements)
remains open; this is `WP-55, 1/N`, not a package completion claim.

## 6. What this PR does about the stack

1. **It does not touch any other PR.** No branch other than
   `arena/e607c9b9-budlum` was pushed. Fixes for other PRs' code belong on
   those PRs' branches, and this session's environment does not push to them
   (the same constraint is recorded in #29, #54, #71, #75 and #77). Where a
   finding is a defect in a shared file, it is recorded here with evidence
   rather than fixed by rewriting another PR's work.
2. **It removes the binding directive from the tree** (directive 0.1.5,
   BLG-288), matching #42, #63, #77, #78. Four conflicting removal PRs exist;
   integration de-duplicates by keeping whichever lands first.
3. **It opens the T-Expansion line with WP-55** (BLG-294) with self-contained
   code on the `bud3` tree; no lock path of any open PR is modified.
4. **It records the stack audit** (this file) instead of FINDINGS.md
   (BLG-289/290/292).
5. **`arena_claude.py` is deliberately unchanged** — five open PRs edit it
   (#24, #34, #43, #45, #60); it is not this branch's concern.

## 7. Recommendations (owner actions, not executed here)

1. **Fix `main` first.** Until `CI` on `cccf1da` is green, every merge in the
   stack moves a red target. The first failing steps are `Gates`,
   `PQ build`, `library test` and `quality` (fmt, clippy).
2. **Appoint one integrator** for `docs/work/PACKAGES.md` and
   `docs/audit/FINDINGS.md`; without it, 25-way and 11-way conflicts are
   guaranteed (BLG-289, BLG-290).
3. **Impose a merge train** ordered by the directive's dependency table
   (15.7) and de-duplicate the `#38 -> #54 -> #64` checkpoint between #77 and
   #80 before either merges (BLG-292).
4. **Assign owners for the T-Expansion eleven** (BLG-294); at minimum WP-55
   and WP-59 to Lane B/C respectively, or declare them explicitly deferred
   after launch.
5. **Repair the shared-append list** (BLG-291): add `xtask/gates/src/main.rs`,
   `src/tests/mod.rs`, `src/chain/blockchain.rs`, `src/execution/executor.rs`,
   or accept the conflicts consciously.
6. **Restore CI runners for open PRs**; pending-forever is how a red base
   ships.
7. **Re-run the audit at M4** and retire the stale "52 open PRs" number
   everywhere (BLG-297).

## 8. Provenance and evidence boundary

- `git diff` of this branch touches only: `src/storage/bud3/live.rs` (new),
  `src/storage/bud3/mod.rs` (append-only), the removal of
  `THE_BUDLUM_DIREKTIF.md`, and this file. No other path is modified.
- No Rust toolchain exists in this workspace; no test was executed locally.
  The Rust files in this PR were syntax-checked with tree-sitter-rust
  (zero ERROR/missing nodes) and read line by line; they were not compiled.
  No finding is claimed closed except BLG-288, whose evidence is the tracked
  tree itself.
- CI was not awaited. `main` is red independently of this branch; this
  branch must not be read as fixing `main`.
- The counts above (63 PRs, 209 files, fan-in numbers, red job names) were
  produced live on 2026-11-06 and re-derivable from the commands in §0.
