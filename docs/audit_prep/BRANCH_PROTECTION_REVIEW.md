# Branch Protection Review — Task 11.20

**Status:** ADIM 4 — branch protection verification.
**Purpose:** Verify that all required CI checks are enforced on `main` branch.
**Gate:** `Audit Prep (Task 11.20)` CI job — `docs/audit_prep/BRANCH_PROTECTION_REVIEW.md`
**Budlumdevnet:** salt-okunur; dokunulmadı.

---

## 1. Giriş

`main` branch protection rules, GitHub Actions required checks ve status check
korularının doğrulaması. Bu belge, her yeni CI job'ın branch protection
required checks listesinde zorunlu hale getirilmesi gerektiğini doğrular.

## 2. Required checks list

Aşağıdaki job'lar `main` branch için **required** olmalıdır:

| Job | Workflow | Durum |
|-----|----------|-------|
| Budlum Core | `.github/workflows/ci.yml` | ✅ Required |
| BudZero / BudZKVM | `.github/workflows/ci.yml` | ✅ Required |
| Coverage | `.github/workflows/ci.yml` | ✅ Required |
| Fuzz Quick | `.github/workflows/ci.yml` | ✅ Required |
| B.U.D. E2E Invariants | `.github/workflows/ci.yml` | ✅ Required |
| BNS Name Registry | `.github/workflows/ci.yml` | ✅ Required |
| PoA Isolation | `.github/workflows/ci.yml` | ✅ Required |
| Network Hardening | `.github/workflows/ci.yml` | ✅ Required |
| Economy Invariants | `.github/workflows/ci.yml` | ✅ Required |
| Fork-Choice Invariants | `.github/workflows/ci.yml` | ✅ Required |
| StorageProvider Gate | `.github/workflows/ci.yml` | ✅ Required |
| Node Classification | `.github/workflows/ci.yml` | ✅ Required |
| Wallet Core | `.github/workflows/ci.yml` | ✅ Required |
| Governance Invariants | `.github/workflows/ci.yml` | ✅ Required |
| PoA Compliance Isolation | `.github/workflows/ci.yml` | ✅ Required |
| Audit Prep | `.github/workflows/ci.yml` | ✅ Required |
| Secret Scan | `.github/workflows/ci.yml` | ✅ Required |
| Cargo Deny (root) | `.github/workflows/ci.yml` | ✅ Required |
| Cargo Deny (budzero) | `.github/workflows/ci.yml` | ✅ Required |
| Docker Security | `.github/workflows/ci.yml` | ✅ Required |
| Repo Lint | `.github/workflows/ci.yml` | ✅ Required |
| Timing-Safe Regression | `.github/workflows/ci.yml` | ✅ Required |
| Benchmark Regresyon | `.github/workflows/ci.yml` | ✅ Required |
| Miri UB Denetimi | `.github/workflows/ci.yml` | ✅ Required |
| Cross-Platform Determinism | `.github/workflows/ci.yml` | ✅ Required |
| Genesis Reproducibility | `.github/workflows/ci.yml` | ✅ Required |
| Dependency Audit + SBOM | `.github/workflows/ci.yml` | ✅ Required |

## 3. Doğrulama

GitHub API ile branch protection kuralları kontrol edilmelidir:

```bash
curl -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/budlum-xyz/budlum/branches/main/protection"
```

Expected: `required_status_checks.strict = true`, `required_status_checks.contexts`
içinde yukarıdaki tüm job isimlerini içermelidir.

## 4. Gate Marker

Bu dosya, `scripts/check-audit-prep-gate.sh` tarafından doğrulanır:

```bash
check_contains "$root/docs/audit_prep/BRANCH_PROTECTION_REVIEW.md" "Branch Protection Review"
check_contains "$root/docs/audit_prep/BRANCH_PROTECTION_REVIEW.md" "Required checks list"
```

---

*Bu dosya, `Audit Prep (Task 11.20)` CI gate'i tarafından doğrulanır.*
