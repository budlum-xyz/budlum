# Testnet directive index — work in progress 2026-11-16

Source: THE_BUDLUM_DIREKTIF (6044 lines, 64 work packages IP-01..IP-64, 267 findings BLG-001..267, TLG gate in Section 18).
This index lists TLG items and their live status. It is not a claim of completion.

## TLG summary (Section 1.3 / 18)
1. All Critical/High findings closed, or feature closed on testnet with proof test — NOT MET (29 unresolved threads, Strix billing block).
2. B.U.D. 3.0 sole storage, old storage code removed — IN PROGRESS (PR #183 stack touches bud3, conflict unresolved at snapshot).
3. Android phone as validator in real testnet rehearsal (store, audit, symbol, reward) — NOT DEMONSTRATED locally; CI Mobile Android job exists (PR #126 run success for Mobile Android & Field Harness).
4. All mobile validators leave suddenly, finality continues, no content loss — NOT DEMONSTRATED.
5. 10% full validators leave, finality delays <=2 checkpoints — NOT DEMONSTRATED.
6. EVM, WASM (CosmWasm ABI), SVM, Move (Aptos), BudZero EEs work with standard tools unchanged — CI Conformance Nightly success on PR #126 head (run 43860950632), but full matrix queued.
7. EVM contract calls CosmWasm contract atomically in same tx — NOT DEMONSTRATED in this pass.
8. README.md / README.tr.md equal Ek A/B, numbers from CI — NOT VERIFIED in this pass (README changed in merge worktree, needs check).
9. CI green, nightly green — NOT MET (rehearsal red, Strix red, queued saturation).

## Operating systems (PLAN)
Only Debian 13 x86_64 available locally. Ubuntu 24.04/22.04, Debian 12, Wolfi, Alpine, Fedora, Rocky, macOS ARM, Windows Server are CI-only. No local multi-OS run claimed.

## Per-directive files
- BNS directive: B1..B13 items — rehearsal scenario 8 was repaired in 00c8918f (Primary offer flow). BNS unresolved Strix threads are in PR #126 (identity_profile, NFT, view receipts) — see strix-ledger.
- Garden directive: 11-step scenario in CI (`Garden scenario (11 steps, real nodes)` job exists, cancelled on PR #183, queued on PR #164). Garden unresolved threads 20 — see ledger.
- Audit directive: this audit-notes set is the deliverable for Aşama 0-2. Aşama 3+ (fix, prove, Strix re-review) is next.

Each TLG item needs commit SHA + CI run number as proof. None claimed here.
