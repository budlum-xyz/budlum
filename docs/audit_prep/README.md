#  Audit Prep Index

**Status:** ADIM 1 — audit-prep evidence map created.
**Scope:** independent auditor entry point for the pre-Task12 mainnet-readiness workstream.
**Budlumdevnet:** read-only reference; this package does not require mutating it.

## Evidence map

| Area | Primary evidence | CI gate |
| --- | --- | --- |
|  threat model v2 | `docs/THREAT_MODEL.md` | `Audit Prep ()` |
|  specs | `docs/spec-review/`, `scripts/check-spec-coverage.sh` | Repo Lint spec coverage gate |
|  economy | `src/chain/fee_market.rs`, `src/tokenomics/reward_pool.rs`, `scripts/check-economy-invariants.sh` | `Economy Invariants ()` |
|  fork choice | `src/domain/fork_choice.rs`, `scripts/check-fork-choice-gate.sh` | `Fork-Choice Invariants ()` |
|  storage | `src/storage/provider.rs`, `src/storage/lifecycle.rs`, `src/domain/storage_deal.rs` | `StorageProvider Gate ()` |
|  node classification | `src/storage/pruning.rs`, `src/cli/commands.rs` | `Node Classification ()` |
|  network hardening | `src/network/peer_manager.rs`, `scripts/check-network-hardening-gate.sh` | `Network Hardening ()` |
|  wallet core | `wallet-core/src/lib.rs`, `scripts/check-wallet-core-gate.sh` | `Wallet Core ()` |
|  governance | `src/core/governance.rs`, `scripts/check-governance-invariants.sh` | `Governance Invariants ()` |
|  PoA compliance | `src/registry/poa_compliance.rs`, `scripts/check-poa-compliance-gate.sh` | `PoA Compliance Isolation ()` |
|  validator keys | `docs/VALIDATOR_KEY_MANAGEMENT.md`, `docs/operations/HSM_BLS_PQ_POLICY.md` | `Audit Prep ()` |\n|  HSM ceremony | `docs/operations/HSM_CEREMONY_REHEARSAL.md` | `Audit Prep ()` |\n|  PoA compliance | `docs/operations/POA_COMPLIANCE_RUNBOOK.md` | `PoA Compliance Isolation ()` |\n|  external audit | `docs/audit_prep/EXTERNAL_AUDIT_DRY_RUN.md` | `Audit Prep ()` |\n|  branch protection | `docs/audit_prep/BRANCH_PROTECTION_REVIEW.md` | `Audit Prep ()` |
|  audit summary | `docs/ARENA4_AUDIT_HARDENING_SUMMARY.md` | `Audit Prep ()` |
|  lockdown | `docs/MAINNET_LOCKDOWN_CHECKLIST.md` | `Audit Prep ()` |
|  readiness review | `docs/audit_prep/MAINNET_READINESS_REVIEW.md` | `Audit Prep ()` |\n|  CI stability | `docs/audit_prep/CI_STABILITY_WINDOW.md` | `Audit Prep ()` |
| ADIM-1 CI hardening verification | `docs/audit_prep/CI_HARDENING_AUDIT_2026-07-21.md` | `Semver Check`, `Determinism`, `Miri UB Check` |

## Review order

1. Start with `docs/TASK11_6_MAINNET_YOL_HARITASI.md` for  dependencies.
2. Read the frozen specs and their reviews under `docs/spec-review/`.
3. Review the Rust modules in the same order as the evidence map.
4. Confirm every named test listed by each `scripts/check-*-gate.sh` script exists and is run by CI.
5. Finish with operational docs:
   - `docs/operations/PRODUCTION_RUNBOOK.md`
   - `docs/VALIDATOR_KEY_MANAGEMENT.md`
   - `docs/operations/HSM_BLS_PQ_POLICY.md`

## Known limits

- Sandbox-local validation cannot compile Rust here because the local environment lacks the Rust toolchain; GitHub CI is the judge.
- Some cryptographic proof paths intentionally use `test-mock-proof` only under tests; production paths require proof envelopes and strict checks.
- PoA compliance hooks are intentionally isolated from permissionless domains and must not be interpreted as global chain policy.
- Wallet-core binding stubs expose public data only; seed/private key export remains out of scope.

## Audit questions to answer before mainnet lockdown

- Are all parameter-changing governance proposals whitelist-bound and activation-timelocked?
- Are all PoA compliance actions impossible to invoke in permissionless domains?
- Are all storage challenge success paths carrying mandatory proof material when a storage root exists?
- Are validator key policies fail-closed for mainnet and aligned with YubiHSM 2 / PKCS#11 operations?
- Are CI gates name-locked so test renames/deletions cannot produce vacuous green?
