# Strix Ledger — 2026-11-16 live snapshot

Source: GitHub API + GraphQL, 2026-11-16 15:12–15:30 Europe/Istanbul.
Repo: budlum-xyz/budlum. Identity: lubosruler (216696759).
Method (Strix imitation, per directive 6): attack surface -> end-to-end code path trace -> test/prove each claim. No claim is closed by comment alone; code or test evidence required.

Strix billing: workspace reached 50-review trial limit on 2026-11-15 (Strix comment 6918060706 / 6909747384). New Strix reviews will not run until upgrade. This ledger is the local Strix-method substitute; it does not replace the required `Strix Security Review` check on `main` protection.

## PR stack (live)

| PR | Head -> Base | Head SHA | Mergeable | Checks (head) | Unresolved threads |
|---|---|---|---|---|---|
| #126 testnet | testnet -> main | f7312e2ab8b3 | True / blocked | 148 total: 65 success, 3 failure, 5 cancelled, 64 queued, 7 in_progress, 2 neutral, 2 skipped | 5 (all strix-security) |
| #164 Garden | garden -> testnet | a600c402094d | True / blocked | 124 total: 14 success, 24 skipped, 82 queued, 4 in_progress, 0 failure | 20 (all strix-security) |
| #183 budlum | budlum-stack -> garden | 10db4c67a95d | False / dirty (conflict) | 87 total: 86 cancelled, 1 skipped, 0 success | 4 (3 strix, 1 coderabbit) |

`main` branch protection: required check `Strix Security Review` only, enforce_admins=true, required_conversation_resolution=true, allow_force_pushes=false. Merge is blocked until Strix passes and conversations resolve. Strix billing limit is therefore a merge blocker external to code.

## Unresolved findings (distinct, grouped by root cause)

### PR #126 — 5 threads, 4 MEDIUM + 1 suggestion

1. `src/storage/bud3/tx.rs:249` MEDIUM — `Bud3Registry::bind_nft` records unverified caller-chosen NFT id; squatting another holder's NFT.
2. `src/wallet/identity_profile.rs:671` MEDIUM — Passport marks forwarding address Verified against BNS root carried in same RPC reply.
3. `src/wallet/identity_profile.rs:613` MEDIUM — Passport evidence cards report node-chosen lineage counts as Verified with no root.
4. `src/wallet/identity_profile.rs:603` suggestion — manifest card Verified on node-served bytes, independent of BNS verdict/commitment. Same root as 2+3.
5. `src/storage/bud3/view.rs:29` MEDIUM — Paid view receipts written into consensus state with no cap/prune; unbounded state growth.

Status: all open. No fix commit yet in this pass. Trace + fix is next work on `testnet` branch (PR #126 branch).

### PR #164 — 20 threads, 5 MEDIUM, 5 LOW, 10 suggestion sub-threads

Garden `src/garden/net.rs` dominates (11 threads):
- MEDIUM `net.rs:258` — Unadmitted peer selects own frame limit in codec, buffering 18 MiB/stream before invite check.
- MEDIUM `net.rs:621` — Greeting budget closes whichever peer sends next; uninvited host frames deny invited validator join.
- MEDIUM `net.rs:387` — 16 half-open TCP sockets exhaust pre-handshake connection budget, shut invite path.
- LOW `net.rs:645` — Greetings from already-admitted peer unbudgeted.
- LOW `chain_actor.rs:3378` — Public RPC reads expose node-local Garden domain record + per-block commitments.
- LOW `types.rs:611` — Host-approval Garden serves whole blocks to invite holder host turned away.
- LOW `storage.rs:103` — Joiner adopts host genesis limits as disk budget, pre-fetches every object.
- LOW `invite.rs:85` — Invite peer entries dialled unverified; pasted invite opens connections to chosen internal endpoints (SSRF-like).
- MEDIUM `blockchain.rs:1470` — Garden domain ids not reserved in settlement registry; third party can squat/shadow Garden Budlum record.
- MEDIUM `blockchain.rs:1761` — Garden block history unbounded node-local registry, deep-cloned on chain actor per public RPC read.

Suggestion threads (10) are code suggestions attached to the above findings (codec slots, invite rule placement, greeting budget table, pending budget, idle timeout, reserved-range predicate, clone arms). They close when their parent finding closes.

Status: all open. Fix on `garden` branch.

### PR #183 — 4 threads

1. `src/storage/bud3/registry.rs:1895` MEDIUM — Single unacknowledged repair share permanently blocks every later repair of its segment. (Strix 4586440186)
2. `src/core/account.rs:1855` LOW — `duty_lane_signers` trusts `Validator.active` instead of bond; unbonded validator keeps zero-fee lane.
3. `src/execution/executor.rs:4132` suggestion — changed RecordRepair call site that reaches refusal. Sub-thread of (1).
4. `mobile/core/src/store.rs:83` CodeRabbit CRITICAL — see PR body. Needs trace.

Status: open. Conflict resolution for PR #183 (4 files) is in progress in this pass; findings (1)+(2) are the semantic core of that conflict (duty-lane + repair). See `findings/pr183-conflict.md`.

## CI failures that are not Strix

### PR #126 Testnet Rehearsal — REAL FAILURE, root cause found

Runs 43860950588 (rehearsal + Testnet Native E2E), jobs 133277315448 / 133277314913, failed 2026-11-16 13:28–13:36 UTC at step 9:
`FAIL: testnet rehearsal failed at ["9. AppBinding register and pay"]; the AppBinding application did not register within 120 s`

Trace (Strix method):
- `xtask/tools/src/testnet_rehearsal.rs:1309 scenario_app_binding` registers PoW domain 4242 via `bud domain register-pow`, then `bud app-binding register`, then polls `bud_getAppBindingApplication` for 60 tries.
- Gate 1: `src/settlement/app_binding.rs:922` — `app_binding_enabled_for_chain_id(ctx.chain_id)`; `src/core/chain_config.rs:234` — enabled only on Devnet (45262), not Testnet (45261). Rehearsal chain is 45261, so Register is refused before registry moves. Test `app_binding_is_closed_on_testnet` (`src/tests/testnet_closed_features.rs:79`) pins this closure.
- Gate 2 (would block next): `ensure_serving_origin` (`app_binding.rs:556`) — PoW domain 4242 is not in canonical set 1..7 (`anchor_recognized_chain`), so refused as "permissionless PoW domain cannot serve as AppBinding trust anchor". Test at `app_binding.rs:3608` pins this refusal for PoW domain 42 on devnet.
- Docs contradiction: commit 3ad19c78 said "active on testnet", commit 0961ac7d reverted docs to "closed on testnet, as the code says". Rehearsal scenario was never updated to match either state.

Conclusion: rehearsal scenario is incompatible with both gates. Fix options recorded in `findings/appbinding-rehearsal.md`. No code fix pushed yet in this pass; decision required: enable AppBinding on Testnet per user directive "testnette olmayacak denen şeyler dahil, hepsini testnete sokmak" + register a non-PoW domain via new CLI, OR remove/skip scenario 9 on testnet with proof test. Weakening the PoW anchor gate is NOT recommended (reintroduces Strix M11).

### PR #183 — 86 cancelled, not failed

All 6 workflow runs for head 10db4c67 cancelled 2026-11-16 14:40:38–41 UTC (CI 43880547303, Rust Quality 43880551787, Typos 43880555754, Cargo Vet 43880559676, Security Audit 43880565096, Audit Guard 43880570068). No job produced a failure log; cancellation is the signal. After conflict fix + push, runs must be re-triggered (rerun failed jobs / new push). Do not claim CI green from cancelled runs.

### PR #126 / #164 — queued / in_progress saturation

PR #126 CI run 43860950466 queued since 11:48 UTC, Determinism 43860950220 queued, Extra Tooling / Diverse Double Compiling / Security Audit in_progress since 11:48 UTC (>3.5h). PR #164 similar after garden push 14:33 UTC. This is runner saturation / fan-out starvation, already partially addressed by head commit f7312e2a "Stop the CI fan-out from starving pull-request gates". Queued is neither pass nor fail.

## Resolved historical threads

PR #126: 337 total threads, 332 resolved. PR #164: 90 total, 70 resolved. PR #183: 34 total, 30 resolved. Resolved threads are not re-opened here; per directive, a resolved thread alone is not proof — spot-check in next pass.

## Evidence files

- `pr-summary-2026-11-16.json` — full check runs, reviews, comments per PR.
- `threads-126.json`, `threads-164.json`, `threads-183.json` — GraphQL review threads (all pages).
- Rehearsal logs: GitHub Actions run 43860950588 logs (downloaded 2026-11-16, step 9 failure at 13:36:16 UTC).
