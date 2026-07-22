# Mainnet Readiness Review — Task 11.20

**Status:** ADIM 1 review ledger.
**Decision rule:** Not a launch approval. A launch approval requires the current main SHA, full CI green, 7-day stability window, and owner sign-off.

## Current review scope

This review covers the pre-Task12 hardening track:

- Task 11.6 specs and ADR alignment
- Task 11.8 economy and fork choice
- Task 11.10 storage and node classification
- Task 11.12 network hardening
- Task 11.14 wallet-core
- Task 11.16 governance
- Task 11.18 PoA compliance isolation
- Task 11.20 audit prep, HSM/key policy and lockdown checklist

## MR-1..MR-10 review ledger

| MR | Criterion | Task 11.20 review position |
| --- | --- | --- |
| MR-1 | CI fully green | Must be checked against latest `origin/main`; no local substitute is accepted |
| MR-2 | Task closure evidence | Evidence map is in `docs/audit_prep/README.md` |
| MR-3 | ZK proof chain | Storage challenge proof paths are strict when storage roots exist |
| MR-4 | Claim hygiene | Mainnet-ready claims remain forbidden unless all MR rows are green |
| MR-5 | Coverage | `Coverage (nextest + llvm-cov, ratchet)` must be green |
| MR-6 | Genesis readiness | `Genesis Reproducibility` and ceremony docs must be green/reviewed |
| MR-7 | Supply chain | deny, SBOM, secret scan, docker security and repo lint gates must be green |
| MR-8 | External/security audit | audit-prep package is ready for dry-run; external audit remains an owner decision |
| MR-9 | Operational smoke | docker/devnet smoke and production runbook rehearsals are launch blockers |
| MR-10 | Announcement discipline | owner sign-off required; no autonomous launch announcement |

## Required sign-offs before launch lock

- Owner / product authority
- Validator operations lead
- Security/audit owner
- HSM/key ceremony custodian quorum
- CI gate owner
- Incident communications owner

## Evidence bundle

- `docs/THREAT_MODEL.md`
- `docs/audit_prep/README.md`
- `docs/MAINNET_LOCKDOWN_CHECKLIST.md`
- `docs/VALIDATOR_KEY_MANAGEMENT.md`
- `docs/operations/PRODUCTION_RUNBOOK.md`
- `docs/operations/HSM_BLS_PQ_POLICY.md`
- `docs/audit_prep/CI_STABILITY_WINDOW.md` — 7-day launch-lock CI stability ledger
- `docs/operations/HSM_CEREMONY_REHEARSAL.md` — YubiHSM 2 ceremony dry-run kanıtları
- `docs/operations/POA_COMPLIANCE_RUNBOOK.md` — PoA compliance oracle/admin/export privacy
- `docs/audit_prep/EXTERNAL_AUDIT_DRY_RUN.md` — auditor entry point + checklist
- `docs/audit_prep/BRANCH_PROTECTION_REVIEW.md` — required checks verification

## Review conclusion template

```text
main_sha: <sha>
ci_summary: <all gates green / red gate list>
stability_window: <start..end>
accepted_residual_risks: <risk IDs>
waivers: <none or waiver IDs>
owner_signoff: <name/date>
```
