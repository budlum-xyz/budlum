# budlum-xyz org roadmap denetimi → Tur 13 / 13.5 / 13.9 / 14

**Kaynak depolar (upstream org):**
| Repo | URL | Rol |
|------|-----|-----|
| Budlum | https://github.com/budlum-xyz/Budlum | L1 Universal Settlement |
| BudZero | https://github.com/budlum-xyz/BudZero | BudZKVM + STARK |
| **B.U.D.** | https://github.com/budlum-xyz/B.U.D. | Broad Universal Database (depolama) |
| budlum.com | https://github.com/budlum-xyz/budlum.com | **Boş** |

**Çalışma fork’ları:** `lubosruler/budlum`, `lubosruler/BudZero` (Tur 1–12.9 burada yapıldı)

---

## 1. Kısa cevap

**Hayır — org’daki *tüm* roadmap’i sadece Tur 13 + 13.5 + 13.9 ile “bitirmiş” sayamayız.**

Ama:
- **Budlum + BudZero** için org README / SPEC / ch12’deki *kodlanabilir* açık maddelerin büyük kısmı 13 serisine sığdırılabilir veya zaten kapalı.
- **B.U.D. (Faz 0–6)** bilinçli olarak **Tur 14** — senin de dediğin gibi ayrı konuşulacak; 13 serisine **sokulmamalı**.
- **Harici audit, TLA+ formal verification, Privacy Layer, AI Execution Layer** “araştırma / süreç / ürün” maddeleri; üç turda *kodla kapanmış roadmap* diye işaretlenemez (en fazla iskelet / placeholder / docs).

---

## 2. budlum-xyz/Budlum — Research Roadmap

Kaynak: org `README.md` → “Research Roadmap”

| Madde (org) | Durum (lubosruler fork, bugün) | 13 / 13.5 / 13.9? |
|-------------|--------------------------------|-------------------|
| Devnet economic hardening | ✅ (erken turlar + tokenomics) | Kapalı |
| Settlement atomicity | ✅ | Kapalı |
| Verified settlement hardening | ✅ (finality adapters, parent links) | Kapalı |
| Verified bridge return path | ✅ + Tur12 PoW mint ban | 13.5’te PoW light-client ile olgunlaştır |
| Sync hardening | ✅ | Kapalı |
| PKCS#11 HSM signer | ✅ Ed25519 consensus; **BLS/PQ disk hâlâ HSM dışı** (B1) | **13.9** (BLS/PQ koruma yolu) |
| BLS finality protocol | ✅ (prevote/precommit + testler) | 13.9’da live coordinator boşlukları taranır |
| RPC dual listener | ✅ + Tur12.5 B2/B3 | 13.5’te runbook/quota netleştirme |
| P2P hardening | ✅ | Kapalı / 13.5 ince ayar |
| Snapshot V2 | ✅ (archive policy org’da “kalan”) | **13.5** archive-node policy docs |
| Observability Prometheus | ✅ kısmen (histograms org’da kalan) | **13.5** histogram/not |
| Deployment docker/systemd | ✅ org’da; fork’ta mevcut | 13.5 runbook |
| **ZKVM optimizations** | ⏳ performans (BudZero Phase 10) | **13.5** (ölçüm + küçük optim) / tam bitmez |
| **Formal verification (TLA+)** | ❌ yok | **13.9 docs iskeleti** — tam model ayrı proje |
| **External audit** | ❌ süreç | **İşaretlenemez “done”** — 13.9 checklist |
| **Privacy layer** | ❌ araştırma | **13 serisi dışı** (veya sadece docs stub) |
| **AI execution layer** | ❌ araştırma | **13 serisi dışı** (docs stub) |

### ch12 Mainnet blockers (org book)

| Blocker / kalan | 13 serisi |
|-----------------|-----------|
| External security audit | Süreç — 13.9 checklist |
| Archive-node policy + backup drills | **13.5** (policy + script/docs) |
| ConsensusStateV2 migration framework | **13.5–13.9** (docs + minimal migration hook) |
| Production runbooks / incident response | **13.5** |
| Per-IP quotas / operator admin methods | Kısmen var → **13.5** netleştir |
| Prometheus latency histograms | **13.5** |
| Governance + BudZKVM + pruning “mainnet v1’de kapalı” | **13.9** policy + config flags net |

---

## 3. budlum-xyz/BudZero — Detailed Roadmap

| Faz (org) | Org iddiası | Fork gerçeği | 13 serisi |
|-----------|-------------|--------------|-----------|
| 0–8 | complete | Büyük ölçüde + security turları | Kapalı / bakımı |
| **9 State & L1 integration** | in progress | Nested backup, save Result, L1 host, pin rebind | **13** bitir (persona + L1 uyum) |
| **10 Performance** | planned | Yok | **13.5** baseline bench |
| **11 Security audit** | planned | İç denetim turları var; harici yok | 13.9 checklist |
| **12 Docs** | active | Türkçe book + README refresh | **13** persona docs + roadmap matrix |
| “All 31 opcodes production” (org README) | ✅ iddia | **Yanlış / tehlikeli:** VerifyMerkle hâlâ experimental + ignore | **13** dürüst status (gate kalır veya 3.5) |
| Z-B valid 64-depth | org “merkle constrained” | **ignore + InvalidProof** | **13** (3.5 hedef; yeşil olmazsa gate + dürüst borç) |

---

## 4. B.U.D. — Broad Universal Database (**Tur 14**)

Kaynak: `BUD_Merkeziyetsiz_Depolama_Vizyonu.md`

| Faz | Konu | 13 serisi? |
|-----|------|------------|
| 0 | Kavramsal harita | Sadece referans |
| 1 | Storage ConsensusDomain | **Tur 14** |
| 2 | İçerik-adresleme (CID/Poseidon) | **Tur 14** |
| 3 | Proof-of-Storage (`VerifyMerkle` bağlama) | **Tur 14** (13’te Z-B olgunlaşması *önkoşul*) |
| 4 | GlobalBlockHeader StorageRoot | **Tur 14** |
| 5 | Operator bond / slash ekonomisi | **Tur 14** |
| 6 | BNS/.bud + devnet pilot | **Tur 14** |

**Tur 13 serisinde B.U.D. kodu yazılmayacak.**  
Not: Faz 3, BudZero’da sağlam `VerifyMerkle` ister → Tur 13 Z-B ilerlemesi Tur 14’ü kolaylaştırır, ama B.U.D. değildir.

---

## 5. Revize Tur 13 / 13.5 / 13.9 (org roadmap ile hizalı)

### Tur 13 — “ZK doğruluğu + her persona için aynı çekirdek”
**Hedef:** User / Dev / Enterprise PoA aynı binary’de uyumlu config; ZK tarafında dürüst production sınırı.

1. **Z-B Commit 3.5 ilerlemesi** (BudZero): pre-round current, single-round path hash, original-only root check, expand gas — *valid 64-depth yeşilse* Production gate aç; değilse gate + ignore + dokümante borç.
2. **Persona paketleri** (Budlum): `config/personas/{user-devnet,developer,enterprise-poa}.toml` + `docs/PERSONAS.md` uyumluluk matrisi.
3. **Org roadmap matrisi** README’ye: budlum-xyz maddeleri × durum (bu dosyanın özeti).
4. **BudZero README** org Phase 9–12 ile senkron, “31 opcode production” iddiasını *gerçekle* hizala.

### Tur 13.5 — “Settlement + operasyon (kurum + devnet)” — **uygulandı**
1. ✅ **PoW light-client / mint:** `pow-header-chain-v1`; header hash/link/root/difficulty/work yeniden hesaplanır, legacy proof mint yapamaz.
2. ✅ **Archive + restore:** fail-closed archive rolü, atomik doğrulanan `.budbak`, retention, boş hedef restore/integrity drill.
3. ✅ **Production runbook:** node, PoA authority, RPC ayrımı, HSM PIN ve incident tetikleri `docs/operations/` altında.
4. ✅ **BudZero Phase 10 baseline:** `budzero/bud-proof/benches/proof_baseline.rs` proof süre/boyut JSON çıktısı.
5. ✅ **RPC quota/admin:** 10k IP bellek tavanlı per-IP pencere; imzasız yönetim yardımcıları operator-only.
6. ✅ **Tek repo:** BudZero workspace `budzero/` altına taşındı; CI ve Docker harici sibling checkout kullanmaz.

### Tur 13.9 — “Mainnet v1 policy + anahtar + devir”
1. **BLS/PQ key protection** (B1 tam kapanışa yaklaşım: mainnet policy + ops path; tam HSM yoksa açıkça “not done”).
2. Finality live path boşluk taraması (ch12 partial → doğrula).
3. Migration / ConsensusStateV2 notları.
4. **External audit checklist** (yapılamaz “done” — teslim paketi).
5. README roadmap: Budlum+BudZero org maddeleri kapanış tablosu (B.U.D. hariç).
6. **DEVİR_RAPORU** güncelle (Arena devri).

### Tur 14 — **B.U.D. only**
Storage domain, content addressing, PoS (proof-of-storage), StorageRoot, ekonomi, BNS/.bud.

---

## 6. Persona uyumu (user / dev / kurum PoA)

| Yetenek | User | Developer | Enterprise PoA | Not |
|---------|------|-----------|----------------|-----|
| Aynı `budlum-core` binary | ✓ | ✓ | ✓ | Persona = config |
| Settlement header verify | ✓ | ✓ | ✓ | |
| Validator / block produce | — | ✓ devnet | ✓ HSM | Mainnet disk key yasak |
| Bridge mint | — | ✓ non-PoW | policy | PoW mint light-client’a bağlı |
| VerifyMerkle in STARK | gated | experimental/test | gated | Org “all production” iddiası yanlış |
| B.U.D. storage | — | — | — | **Tur 14** |

---

## 7. Sonuç cümlesi

- **Org Budlum + BudZero roadmap’inin kodlanabilir omurgası** → Tur 13–13.9 ile *kapatılmaya çalışılır* ve README’de madde madde işaretlenir.  
- **Org’un “research / audit / privacy / AI” satırları** → 13.9’da checklist; “bitti” denmez.  
- **B.U.D. tüm fazlar** → **Tur 14**, 13 serisine karışmaz.  
- **budlum.com** → boş; 13 serisi kapsamı dışı.

Bu denetim, “roadmap bitiyor mu?” sorusuna: **L1+zkVM operasyonel roadmap evet hedeflenir; org’un tüm araştırma + B.U.D. hayır — bilinçli ayrım.**
