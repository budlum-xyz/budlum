# External Audit Dry-Run — Task 11.20

**Status:** ADIM 2 — audit prep evidence for independent review.
**Purpose:** Provide an independent auditor with a self-contained entry point
to compile, test, and review the codebase without prior context.
**Gate:** `Audit Prep (Task 11.20)` CI job — `docs/audit_prep/EXTERNAL_AUDIT_DRY_RUN.md`
**Budlumdevnet:** salt-okunur; dokunulmadı.

---

## 1. Auditor entry point

### 1.1 Repository

```
git clone https://github.com/budlum-xyz/budlum.git
cd budlum
git checkout main  # or latest tagged release
```

### 1.2 Build

```bash
# Rust toolchain (pinned in rust-toolchain.toml)
rustup install 1.94.0
cargo build --release

# Wallet-core (separate crate)
cargo build --manifest-path wallet-core/Cargo.toml --release
```

### 1.3 Test

```bash
# Core library tests
cargo test --lib

# Wallet-core tests
cargo test --manifest-path wallet-core/Cargo.toml

# Gate-verified named tests (non-vacuous)
bash ./scripts/check-economy-invariants.sh --self-test
bash ./scripts/check-network-hardening-gate.sh --self-test
bash ./scripts/check-storage-provider-gate.sh --self-test
bash ./scripts/check-node-classification-gate.sh --self-test
bash ./scripts/check-wallet-core-gate.sh --self-test
bash ./scripts/check-governance-invariants.sh --self-test
bash ./scripts/check-poa-compliance-gate.sh --self-test
bash ./scripts/check-audit-prep-gate.sh --self-test
```

### 1.4 CI status

```
https://github.com/budlum-xyz/budlum/actions
```

All 30 check-runs must be green on the target SHA.

---

## 2. Auditor persona checklist

| # | Item | Evidence |
|---|------|----------|
| 1 | Can clone + build from clean state | `cargo build --release` succeeds |
| 2 | Can run all tests | `cargo test --lib` → 0 failures |
| 3 | Can run gate self-tests | All `check-*-gate.sh --self-test` pass |
| 4 | Can read all spec docs | `docs/spec-review/` + `docs/BUDLUM_TASK11.md` |
| 5 | Can verify audit prep index | `docs/audit_prep/README.md` evidence map |
| 6 | Can check threat model | `docs/THREAT_MODEL.md` v2 closure matrix |
| 7 | Can verify lockdown checklist | `docs/MAINNET_LOCKDOWN_CHECKLIST.md` |
| 8 | Can verify HSM policy | `docs/VALIDATOR_KEY_MANAGEMENT.md` + `HSM_BLS_PQ_POLICY.md` |

---

## 3. Bug bounty scope

- **Program:** Bug bounty program documented in `docs/BUG_BOUNTY.md`
- **Scope:** All code under `src/`, `budzero/`, `wallet-core/`
- **Out of scope:** `budlumdevnet/` (read-only reference), docs-only changes
- **Severity tiers:** 4 tiers (Critical, High, Medium, Low) with reward ranges

---

## 4. Reading time estimate

| Component | Lines | Estimated review time |
|-----------|-------|----------------------|
| `src/` (core) | ~50,000 | 8–12 hours |
| `budzero/` (ZKVM) | ~15,000 | 4–6 hours |
| `wallet-core/` | ~1,200 | 1–2 hours |
| `docs/` | ~50,000 | 6–8 hours |
| **Total** | ~117,000 | **20–30 hours** |

---

## 5. Known findings (audit trail)

| ID | Finding | Severity | Status |
|---|---------|----------|--------|
| V24 | Bridge root scope | 🔴 | ✅ FIXED (regression test) |
| V37/V38 | VerifyMerkle STARK | 🔴 | ✅ FIXED (strict proof mandatory) |
| V86 | Escrow release/reclaim | 🔴 | ✅ FIXED (archive_settled_payment) |
| V89 | AiAgentPayment audit trail | 🔴 | ✅ FIXED (settled_agent_payments) |
| V95 | Reorg split-brain | 🔴 | ✅ FIXED (state reload) |
| V106 | Sweep balance refund | 🔴 | ✅ FIXED (add_balance in sweep) |
| V110 | VerifyInference weak commitment | 🔴 | ✅ FIXED (STARK prove/verify) |
| V116 | AiAgentPayment proto collision | 🔴 | ✅ FIXED (separate proto types) |
| V119 | Sync-committee 1-pubkey | 🔴 | ✅ FIXED (aggregate verify) |
| V144 | Supply cap inflation | 🔴 | ✅ FIXED (total_bud_committed) |

**Toplam:** 164 bulgu (V22-V208), 105 kapatıldı, 59 açık (çoğu ⚪ düşük).

---

## 6. Gate Marker

Bu dosya, `scripts/check-audit-prep-gate.sh` tarafından doğrulanır:

```bash
check_contains "$root/docs/audit_prep/EXTERNAL_AUDIT_DRY_RUN.md" "External Audit Dry-Run"
check_contains "$root/docs/audit_prep/EXTERNAL_AUDIT_DRY_RUN.md" "Auditor persona checklist"
```

---

*Bu dosya, `Audit Prep (Task 11.20)` CI gate'i tarafından doğrulanır.*
