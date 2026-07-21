# Phase 11.20 Audit Prep Index

**Status:** ADIM 1 — audit-prep evidence map created.
**Scope:** independent auditor entry point for the pre-Phase12 mainnet-readiness workstream.
**Budlumdevnet:** read-only reference; this package does not require mutating it.

## Evidence map

| Area | Primary evidence | CI gate |
| --- | --- | --- |
| Phase 11.20 threat model v2 | `docs/THREAT_MODEL.md` | `Audit Prep (Phase 11.20)` |
| Phase 11.6 specs | `docs/spec-review/`, `scripts/check-spec-coverage.sh` | Repo Lint spec coverage gate |
| Phase 11.8 economy | `src/chain/fee_market.rs`, `src/tokenomics/reward_pool.rs`, `scripts/check-economy-invariants.sh` | `Economy Invariants (Phase 11.8)` |
| Phase 11.8 fork choice | `src/domain/fork_choice.rs`, `scripts/check-fork-choice-gate.sh` | `Fork-Choice Invariants (Phase 11.8)` |
| Phase 11.10 storage | `src/storage/provider.rs`, `src/storage/lifecycle.rs`, `src/domain/storage_deal.rs` | `StorageProvider Gate (Phase 11.10)` |
| Phase 11.10 node classification | `src/storage/pruning.rs`, `src/cli/commands.rs` | `Node Classification (Phase 11.10)` |
| Phase 11.12 network hardening | `src/network/peer_manager.rs`, `scripts/check-network-hardening-gate.sh` | `Network Hardening (Phase 11.12)` |
| Phase 11.14 wallet core | `wallet-core/src/lib.rs`, `scripts/check-wallet-core-gate.sh` | `Wallet Core (Phase 11.14)` |
| Phase 11.16 governance | `src/core/governance.rs`, `scripts/check-governance-invariants.sh` | `Governance Invariants (Phase 11.16)` |
| Phase 11.18 PoA compliance | `src/registry/poa_compliance.rs`, `scripts/check-poa-compliance-gate.sh` | `PoA Compliance Isolation (Phase 11.18)` |
| Phase 11.20 validator keys | `docs/VALIDATOR_KEY_MANAGEMENT.md`, `docs/operations/HSM_BLS_PQ_POLICY.md` | `Audit Prep (Phase 11.20)` |
| Phase 11.20 lockdown | `docs/MAINNET_LOCKDOWN_CHECKLIST.md` | `Audit Prep (Phase 11.20)` |
| Phase 11.20 readiness review | `docs/audit_prep/MAINNET_READINESS_REVIEW.md` | `Audit Prep (Phase 11.20)` |\n| Phase 11.20 CI stability | `docs/audit_prep/CI_STABILITY_WINDOW.md` | `Audit Prep (Phase 11.20)` |

## Review order

1. Start with `docs/PHASE11_6_MAINNET_YOL_HARITASI.md` for phase dependencies.
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
