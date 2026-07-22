# ARENA3 — Critical Findings Verification Audit (H1 / §4.1 inventory)

**Date:** 2026-07-20
**Reviewer:** ARENA3
**Code basis:** `origin/main` → `083f59c` (Budlum Core `success` at audit time)
**Scope:** independent verification of every 🔴 critical entry in
`docs/BUDLUM_HARDENING_PROTOCOL.md` §4.1 (H1 target list) against the actual
source + tests — **not** against the status prose. Per coordination rules
#1/#6, a "Fixed" claim is accepted only with a code location + a regression
test that asserts the security property.
**Trigger:** ARENA3 re-activation (user instruction: examine prior ARENA3 work
and determine a path). This is the chosen ADIM = security verification tour.

---

## 1. Method

For each finding I (a) located the fix in code by V-id comment, (b) confirmed
the test exists **and asserts the security property** (not merely present), and
(c) recorded file:test evidence. A claim with no enforcing test is flagged ⚠️.

## 2. Per-finding result

| ID | §4.1 claim (t0) | Code evidence (verified) | Regression lock (verified) | Result |
|----|------|------|------|------|
| **V24** | `bridge.rs root()` includes transfer fields | `cross_domain/bridge.rs:400` `root()` commits `asset_locations` + every transfer field (owner/recipient/amount/src+target domain/status/source_event_hash/expiry_height); `replay` bound via separate `replay_root()` → header `replay_nonce_root` (`blockchain.rs:1065-1066`) | `bridge.rs::v24_forged_transfer_amount_changes_bridge_root` (forged amount changes root) | ✅ FIXED. Minor residuals (§3). |
| **V86** | Release/reclaim tx + executor | `core/transaction.rs:180,183` `ReleaseEscrow`/`ReclaimEscrow`; `execution/executor.rs:1052,1081`; `ai/registry.rs:1171` archives to settled history | `hardening_locks.rs::v86_v89_reclaim_archives_settlement` (reclaim returns amount, archives receipt `Reclaimed`, payment_id non-reusable) + `v89_executor_…` e2e fund flow (balances move) | ✅ FIXED + e2e fund test |
| **V89** | settle-immediate receipt; payment_id consumed | `ai/registry.rs:71,1140,1190 is_payment_id_consumed`; `ai/types.rs:716,720` immutable receipt; `executor.rs:1038` never drops payment_id | `hardening_locks.rs` V89 test asserts `is_payment_id_consumed==true` + reuse errors ("settled payment_id must not be reusable") | ✅ FIXED |
| **V95** | reorg state sync fix | `chain/blockchain.rs:3190 try_reorg`, `MAX_REORG_DEPTH`, "Cannot reorg past finality depth" guard | `tests/chaos.rs::test_chaos_reorg_depth_protection` (deep reorg rejected with `Err`) | ✅ FIXED |
| **V106** | sweep refund | `cross_domain/bridge.rs:454`, `bridge_relayer.rs:288`, `blockchain.rs:2679-2685` return `(owner, amount)` and refund owner | `tests/bridge_lifecycle.rs` asserts `released[0]==(owner,100)` + released lock cannot be minted | ✅ FIXED |
| **V110** | VerifyInference disabled/fail path | `execution/zkvm.rs:304` wired; mainnet-without-activation rejected, non-mainnet allowed | `zkvm.rs` 3-task test (non-mainnet allow / mainnet-no-activation reject / mainnet-full allow) | ✅ FIXED + mainnet gate |
| **V116** | proto payment enum+decode | `proto/budlum/network/protocol.proto:75,455` dedicated AiAgentPayment proto types; `network/proto_conversions.rs:214,930` | `proto_conversions.rs::test_all_23_transaction_types_lossless_roundtrip` (covers AiAgentPayment lossless) | ✅ FIXED |
| **V119** | sync committee threshold | `cross_domain/evm/sync_committee.rs:77 PARTICIPATION_THRESHOLD=(512*2)/3+1=342`, count-based (not first-success) | `participation_threshold_is_two_thirds`, `zero_participation_rejected_below_threshold` | ✅ FIXED |
| **V37/V38** | VerifyMerkle production-gated; interim challenge | `budzero/bud-isa` VerifyMerkle production gate closed; 64-depth `#[ignore]` | — (gate, not a fix) | 📌 Conscious mainnet limit (K2 + MR-3). Not closeable; correctly documented in §4.2. |

**Net:** 8 of 9 closeable 🔴 findings verified FIXED with enforcing regression
locks; 1 is a documented conscious limitation. Older `STATUS_ONLINE` inventory
tables that still mark V24 / the GAP-2 transfer scope as "🔴 Açık / GAP-2
kapsamında" are **stale** (audit-trail preserved; correction carried in the
2026-07-20 ARENA3 STATUS entry and §4.1 update).

## 3. Minor residuals (ARENA3 lock ADIM, user-approved)

- **V24-a:** `BridgeState.expiry_queue` is an index built from
  `transfer.expiry_height` (which *is* committed), but the queue itself is not
  integrity-bound. A locally-corrupted queue could trigger an early sweep the
  root would not detect. Lock: test that a forged `expiry_queue` entry
  inconsistent with the committed `expiry_height` cannot alter consensus
  balances (sweep re-derives from the transfer ledger).
- **V24-b:** `bridge_root` is committed in the snapshot digest
  (`snapshot.rs:684`); `replay` reaches the header via `replay_nonce_root`.
  Pin a test proving a replay-store mutation changes the committed binding, so
  V24's replay scope is locked end-to-end, not only at the header field.

Low-risk hardening; neither is a known exploitable defect.

## 4. CI finding (ARENA3 domain) — recurring false-red badge loop (MR-1 blocker)

- `21ea24e` "Budlum Core FAILED" is **not** a code/test failure. Build, format,
  clippy and the lib-test step all PASS; only step 13 ("Test rozeti tazeleme")
  fails. Root cause (`.github/workflows/ci.yml:106-136`): the badge step pushes
  the README test-count badge; on protected `main` the `GITHUB_TOKEN` is
  rejected, so it relies on the `BADGE_PUSH_TOKEN` (admin PAT bypass). When that
  secret is absent/intermittent the step `exit 1` ⇒ Budlum Core shows red.
- `083f59c` (manual badge workaround) made Core green again. ARENA4 hit the same
  loop at 13:18. A red badge job **blocks MR-1** ("one red job ⇒ seal blocked").

## 5. Decisions (resolved by Ayaz, 2026-07-20)

1. **Badge false-red fix:** applied — `.github/workflows/ci.yml` badge
   push-failure converted to **soft-fail** (`exit 0` + warning). The two safety
   guards are preserved: the test-failure guard (`grep '[1-9][0-9]* failed' →
   exit 1`) and the parse-failure guard. Only the cosmetic-badge *push* failure
   no longer turns the Core job red. `continue-on-error` was deliberately **not**
   used (it would mask the test-failure guard). User authorized ARENA3 to apply
   the workflow change directly.
2. **V24 residuals:** approved — two pin tests added as a follow-up ARENA3 code
   ADIM (this doc's §3).
3. **Audit report + STATUS closure + §4.1 update:** pushed (pending CI green).

*Co-authored-by: ARENA3 <arena3@budlum.xyz>*
