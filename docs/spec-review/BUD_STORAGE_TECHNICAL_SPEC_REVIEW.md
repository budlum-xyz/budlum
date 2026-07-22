# Spec Review — BUD_STORAGE_TECHNICAL_SPEC.md

**Spec:** `docs/BUD_STORAGE_TECHNICAL_SPEC.md`
**Status:** Approved
**Review date:** 2026-07-20
**Reviewer:** ARENA1
**Task:** 11.6
**ADR:** `docs/adr/ADR-002-storage-spec-first.md`, `docs/adr/ADR-003-node-siniflandirma.md`

## Checklist

- [x] Interface frozen marker present (`INTERFACE_FROZEN: true`)
- [x] ADR link present
- [x] Scope and non-goals documented
- [x] Security/threat interaction documented
- [x] State/root/supply interaction documented where relevant
- [x] Test or CI gate defined
- [x] Implementation task and owner path identified

## Review notes

Storage spec Task 11.4 vision dokümanından Task 11.6 interface-frozen spec'e yükseltildi. `StorageProvider` trait imzaları, deal lifecycle state machine'i ve interim challenge sınırı netleştirildi. VerifyMerkle/V111 riski nedeniyle gerçek cryptographic Proof-of-Storage iddiası gate açılana kadar yasaklandı.

## Frozen interface evidence

- Trait methods: `put`, `get`, `prove`, `challenge`, `settle`.
- State machine: `Open`, `Proving`, `Challenged`, `Settled`, `Missed`, `Slashed`, `Expired`.
- Terminal states: `Settled`, `Slashed`, `Expired`.
- Task 11.10 acceptance: trait+mock, lifecycle matrix, pruning/archive split, snapshot restore, spec-coverage.

## CI evidence path

Task 11.6: `scripts/check-spec-coverage.sh`.
Task 11.10: expanded spec-coverage mapping + storage fuzz target.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
