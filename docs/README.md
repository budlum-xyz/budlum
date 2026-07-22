# Budlum Documentation

- [Architecture Atlas](ARCHITECTURE.md) — system, trust-boundary, signing, bridge, snapshot, durability, BudZero, AI, B.U.D., CI and mainnet-launch diagrams
- [Reports index + naming standard](archive/REPORTS_INDEX.md) — tüm rapor/denetim/plan belgelerinin kanonik indeksi (EN canonical body + TR özet kuralı, Q6 2026-07-16)

Choose a language:

- [Turkce dokumantasyon](tr/book/README.md)
- [English documentation](en/book/README.md)

Current production-readiness status:

- **[Budlum Full Hardening Protocol](BUDLUM_HARDENING_PROTOCOL.md)** — kanonik sertleştirme rejimi (H0–H9 kapıları, V-bulgu imhası, fuzz/HSM/ağ/ops, "tam sertleştirilmiş" mühür)


- [Turkce production hardening durumu](tr/book/ch12_production_hardening.md)
- [English production hardening status](en/book/ch12_production_hardening.md)

Specialised deep-dives:

- [ARENA4 approved systems roadmap](ARENA4_APPROVED_SYSTEMS_ROADMAP_2026-07-20.md) — Pollen, AI read gate, D-Web Passport, Relayer Policy, Atlas ve onaylanan sistemlerin uygulama sırası
- [ implementation report](archive/TASK0.37_RAPOR.md)
- [Production / enterprise PoA runbook](operations/PRODUCTION_RUNBOOK.md)
- [Archive backup/restore runbook](operations/ARCHIVE_AND_BACKUP.md)
- [Post-quantum security architecture ()](03_post_quantum_security.md) — Dilithium5 integration, hybrid roadmap, threat model
- [Budlum'un Çözebileceği Paradigma Kaymaları](03_paradigma_analizi.md) — 7 yapısal sorun, 7 paradigma kayması, 2035 vizyonu (Türkçe)

## Integrated BudZKVM

`budlum-core` consumes the ZK execution environment from the in-tree
[`budzero/`](../budzero/README.md) workspace via path dependencies on
`bud-isa`, `bud-vm`, and `bud-proof`. This  monorepo layout makes one
commit the compatibility boundary for settlement and proof verification.
