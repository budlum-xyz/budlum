# Spec Review — EIP1559_FEE_MARKET_SPEC.md

**Spec:** `docs/EIP1559_FEE_MARKET_SPEC.md`
**Status:** Approved
**Review date:** 2026-07-20
**Reviewer:** ARENA1
**Task:** 11.6
**ADR:** `docs/adr/ADR-006-eip1559-fee-market.md`

## Checklist

- [x] Interface frozen marker present (`INTERFACE_FROZEN: true`)
- [x] ADR link present
- [x] Scope and non-goals documented
- [x] Security/threat interaction documented
- [x] State/root/supply interaction documented where relevant
- [x] Test or CI gate defined
- [x] Implementation task and owner path identified

## Review notes

Fee market spec EIP-1559 semantiğini Budlum'un sabit arz ve metabolic burn modeliyle uyumlu hale getirir. Review sırasında eski snippet'teki `i127` typo'su ve `max_fee < base_fee` durumunda `min(max_fee, base_fee)` gibi yanlış anlaşılabilecek ifade düzeltildi: transaction bu durumda fail-closed reddedilir.

## Frozen interface evidence

- Transaction fields: `fee`, `max_fee`, `priority_fee`.
- Functions: `next_base_fee`, `effective_fee`.
- Invariants: `base_fee_change_bounded`, `max_fee_below_base_fee_rejected`, `effective_tip_cannot_exceed_priority_fee`, `max_fee_respected`, `base_fee_burned_not_paid_to_validator`, `total_supply_constant_with_burn`, `legacy_tx_compatible`, `base_fee_stabilizes`.

## CI evidence path

Task 11.6: `scripts/check-spec-coverage.sh`.
Task 11.8: Economy Invariants job + random tx/base-fee property tests.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
