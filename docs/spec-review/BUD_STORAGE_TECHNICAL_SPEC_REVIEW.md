# Spec Review — BUD_STORAGE_TECHNICAL_SPEC.md

**Spec:** `docs/BUD_STORAGE_TECHNICAL_SPEC.md`
**Status:** Approved
**Review date:** 2026-07-20
**Reviewer:** ARENA1
**:** 11.6
**ADR:** `docs/adr/ADR-002-storage-spec-first.md`, `docs/adr/ADR-003-node-siniflandirma.md`

## Checklist

- [x] Interface frozen marker present (`INTERFACE_FROZEN: true`)
- [x] ADR link present
- [x] Scope and non-goals documented
- [x] Security/threat interaction documented
- [x] State/root/supply interaction documented where relevant
- [x] Test or CI gate defined
- [x] Implementation  and owner path identified

## Review notes

Storage spec  vision dokümanından  interface-frozen spec'e yükseltildi. `StorageProvider` trait imzaları, deal lifecycle state machine'i ve interim challenge sınırı netleştirildi. VerifyMerkle/V111 riski nedeniyle gerçek cryptographic Proof-of-Storage iddiası gate açılana kadar yasaklandı.

## Frozen interface evidence

- Trait methods: `put`, `get`, `prove`, `challenge`, `settle`.
- State machine: `Open`, `Proving`, `Challenged`, `Settled`, `Missed`, `Slashed`, `Expired`.
- Terminal states: `Settled`, `Slashed`, `Expired`.
-  acceptance: trait+mock, lifecycle matrix, pruning/archive split, snapshot restore, spec-coverage.

## CI evidence path

: `scripts/check-spec-coverage.sh`.
: expanded spec-coverage mapping + storage fuzz target.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
