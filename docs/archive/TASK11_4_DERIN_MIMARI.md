# Task 11.4 — Derin Sistem Mimarisi (Kullanıcı Talimatı, 2026-07-20)

> **Yazar:** ARENA1 (görev yöneticisi), 2026-07-20.
> **Komut beklenmeden devam edilir.** 4 ana alan + kalan Task 4/5/7.

---

## Kapsam

### A. Storage (en büyük boşluk)
1. **B.U.D. storage vision → teknik spec:** `docs/BUD_STORAGE_TECHNICAL_SPEC.md`
   - Vision dokümanı (`BUD_Merkeziyetsiz_Depolama_Vizyonu.md`) → uygulanabilir spec
   - Gorev 1-6 detay: ContentId, Manifest, Deal, Challenge, Proof-of-Storage, BNS
   - Mevcut kod (`src/storage/`, `src/domain/storage_deal.rs`) ile gap analizi
2. **State pruning / archival vs full node:**
   - `docs/STATE_PRUNING_SPEC.md` — pruning stratejisi (full/archive/light)
   - Snapshot retention, historical state query (archive node)

### B. Protokol Derinliği
3. **Domain-özel fork-choice:** `docs/DOMAIN_FORK_CHOICE_SPEC.md`
   - PoW: longest-chain (implemented)
   - PoS/BFT: instant finality (FinalityCert)
   - PoA: authority quorum
4. **Domain lifecycle:** `docs/DOMAIN_LIFECYCLE_SPEC.md`
   - start/stop/upgrade domain
   - ConsensusDomain primitive → operational lifecycle
5. **Light client / SPV:** `docs/LIGHT_CLIENT_SPEC.md`
   - Interface tasarımı (erişken ama erken)

### C. Ağ Sertleştirme
6. **Node discovery:** `docs/NETWORK_HARDENING_SPEC.md`
   - Kademlia DHT, NAT traversal
   - Peer reputation/banlama
   - Eclipse attack koruması

### D. Wallet Ekosistemi (core crate bitince)
7. **Mobile UI:** uniffi → Kotlin/Swift binding dökümanı
8. **Browser extension:** wasm-bindgen → JS/TS binding dökümanı
9. **Multisig / social recovery:** scope analizi

### Kalan Task'lar (7 görev listesinden)
- **Task 4:** PoA KYC/whitelist onboarding modülü
- **Task 5:** bud-cli tx/query subcommands
- **Task 7:** Metrics/observability per-domain

---

## Öncelik (sıralı yürütme)

1. B.U.D. Storage Technical Spec (en büyük boşluk)
2. State Pruning Spec
3. Domain Fork-Choice Spec
4. Domain Lifecycle Spec
5. Light Client Spec
6. Network Hardening Spec
7. Task 7: Metrics/observability (kod)
8. Task 4: PoA onboarding (kod)
9. Wallet ecosystem binding docs
