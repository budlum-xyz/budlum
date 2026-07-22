# Spec Review — DOMAIN_FORK_CHOICE_SPEC.md

**Spec:** `docs/DOMAIN_FORK_CHOICE_SPEC.md`
**Status:** Approved
**Review date:** 2026-07-20
**Reviewer:** ARENA1
**Task:** 11.6
**ADR:** `docs/adr/ADR-007-per-domain-fork-choice.md`

## Checklist

- [x] Interface frozen marker present (`INTERFACE_FROZEN: true`)
- [x] ADR link present
- [x] Scope and non-goals documented
- [x] Security/threat interaction documented
- [x] State/root/supply interaction documented where relevant
- [x] Test or CI gate defined
- [x] Implementation task and owner path identified

## Review notes

Domain fork-choice spec ADR-007 ile hizalandı: PoW most-work, PoS LMD-GHOST, BFT instant finality, PoA round-robin authority schedule. Önceki draft'taki PoA hash-mix ifadesi karar metniyle çeliştiği için spec-level hedef olarak round-robin donduruldu. Domain lifecycle start/pause/drain/retire/upgrade geçişleri netleştirildi.

## Frozen interface evidence

- Trait: `ConsensusDomainForkChoice::fork_choice(&self, candidates)`.
- Data structs: `ForkCandidate`, `ResolvedHead`.
- Lifecycle enum: `Proposed`, `Active`, `Paused`, `Draining`, `Retired`.
- Domain rules: PoW most-work, PoS LMD-GHOST, BFT QC finality, PoA round-robin.

## CI evidence path

Task 11.6: `scripts/check-spec-coverage.sh`.
Task 11.8: fork-choice fuzz + lifecycle invariant tests.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
