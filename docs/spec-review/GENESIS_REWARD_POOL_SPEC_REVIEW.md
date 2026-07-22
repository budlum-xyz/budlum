# Spec Review — GENESIS_REWARD_POOL_SPEC.md

**Spec:** `docs/GENESIS_REWARD_POOL_SPEC.md`
**Status:** Approved
**Review date:** 2026-07-20
**Reviewer:** ARENA1
**:** 11.6
**ADR:** `docs/adr/ADR-001-genesis-reward-pool.md`

## Checklist

- [x] Interface frozen marker present (`INTERFACE_FROZEN: true`)
- [x] ADR link present
- [x] Scope and non-goals documented
- [x] Security/threat interaction documented
- [x] State/root/supply interaction documented where relevant
- [x] Test or CI gate defined
- [x] Implementation  and owner path identified

## Review notes

Genesis reward pool spec sabit 100M arz ilkesine uygun şekilde pre-allocation modelini dondurur. V144 sonrası supply denominator'ı yalnız circulating değil, staked ve unbonding BUD'ları da kapsayacak şekilde açıklandı. Slash ve treasury etkileşimi yeni emisyon yaratmayacak şekilde sınırlı tutuldu.

## Frozen interface evidence

- Config keys: `validation_reward_pool`, `validation_pool_epochs`, `treasury_pool`, `reward_pool_start_epoch`.
- Runtime functions: `reward_for_epoch`, `apply_epoch_rewards`.
- Invariants: `total_supply_constant`, `pool_non_negative`, `slashed_gets_no_reward`, `inactive_gets_no_reward`, `stake_proportional`, `pool_exhaustion_halts`, `treasury_not_validator_reward`.

## CI evidence path

: `scripts/check-spec-coverage.sh`.
: Economy Invariants job + 10K epoch simulation.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
