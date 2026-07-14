# Budlum Documentation

Choose a language:

- [Turkce dokumantasyon](tr/book/README.md)
- [English documentation](en/book/README.md)

Current production-readiness status:

- [Turkce production hardening durumu](tr/book/ch12_production_hardening.md)
- [English production hardening status](en/book/ch12_production_hardening.md)

Specialised deep-dives:

- [Tur 13.5 implementation report](TUR13_5_RAPOR.md)
- [Production / enterprise PoA runbook](operations/PRODUCTION_RUNBOOK.md)
- [Archive backup/restore runbook](operations/ARCHIVE_AND_BACKUP.md)
- [Post-quantum security architecture (Tur 8)](03_post_quantum_security.md) — Dilithium5 integration, hybrid roadmap, threat model
- [Budlum'un Çözebileceği Paradigma Kaymaları](03_paradigma_analizi.md) — 7 yapısal sorun, 7 paradigma kayması, 2035 vizyonu (Türkçe)

## Integrated BudZKVM

`budlum-core` consumes the ZK execution environment from the in-tree
[`budzero/`](../budzero/README.md) workspace via path dependencies on
`bud-isa`, `bud-vm`, and `bud-proof`. This Tur 13.5 monorepo layout makes one
commit the compatibility boundary for settlement and proof verification.
