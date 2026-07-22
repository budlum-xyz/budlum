# Budlum — Task 11: Mainnet Lockdown & Açık Bulgu Kapanışı

> **Amaç:** Projenin tüm açık işlerini — ARENAX'in 28 açık V-bulgusu (V22-V71),
> mainnet hazırlık talimatının 18 maddesi, MR-1..10 kalanlarını — tek bir
> koordineli gorevda kapatmak. Mainnete kadar **hiçbir açık Kritik/Yüksek bulgu
> kalmamalı**.
>
> **Yazar:** ARENA1 (görev yöneticisi), 2026-07-19.
> **Temel:** main `f6931d2` · 964 Core lib + 94 BudZero = ~1058 test · 19/19 CI yeşil.
> **Kaynak:** `docs/mainnet-hazirligi-talimati.md` + `docs/STATUS_ONLINE.md` ARENAX denetimleri.

---

## 0. Prensip (AI Ajan Talimatı §2 + §5)

Task 11 bir sprint değil — **temel atma işi**. Her satır yarın üzerine bina
kurulacak bir taş. Acele yok; her bulgu CI yeşil olmadan kapanmış sayılmaz.
Karar noktalarında soru sorulur (§4). Dışarıdan gelen commit'ler CI + diff
ile doğrulanır (§6).

---

## 1. Mevcut Durum Snapshot (2026-07-19)

**Tamamlanan (Task 1-10.5):**
- Multi-consensus L1 (PoW/PoS/PoA/BFT/ZK/Storage) + bridge lifecycle
- BudZKVM in-tree + VerifyMerkle (Production-gated, MR-3 açık)
- B.U.D. storage Gorev 1-2-5 iskeleti + pollen marketplace P0
- AI Inference attestation layer (P0-P5 ship edildi)
- F10 EVM ChainAdapter kompletness (RLP+MPT+receipt+header+sync-committee+relayer binary+Bud→ETH)
- P2 schema-4 snapshot (GAP-1 imza + GAP-2 hash-kapsam + B2 AssetId struct)
- Modül README'leri (Bölüm 4) + dashboard
- Talimat repoda (`docs/AI_AJAN_TALIMATI_GENEL.md`)

**ARENAX denetim durumu (V22-V71):**
- Toplam 40 bulgu · 12 kapatıldı · **28 açık**
- 3 🔴 Kritik açık (V24, V37, V38)
- 7 🟡 Yüksek açık
- 18 ⚪ Düşük açık

---

## 2. Açık Kritik Bulgular (🔴 Mainnet Blocker)

### V24 — BridgeState root scope eksik
**Sorun:** `BridgeState.root()` asset_locations'ı hash'liyor ama transfer
metadata'sını (amount/owner/recipient/status) kapsamıyor. Forge/snapshot
yoluyla transfer verisi değiştirilebilir → köprü fon drain.
**Çözüm:** `root()` tüm transfer alanlarını kapsasın (hash'e ekle).
**Kabul:** Forged transfer → root mismatch testi. GAP-2 kapsamında bağlantılı.
**Sorumlu:** ARENA1 (cross_domain domain'i).

### V37 — B.U.D. challenge answer hash doğrulaması
**Sorun:** `answer_challenge` `range_hash`'i kaydediyor ama operatör'ün gerçekten
o byte-range'i sakladığını kanıtlamıyor. ZK proof entegrasyonu gerekli.
**Çözüm:** Gorev 3 VerifyMerkle entegrasyonu (MR-3 bağımlılığı). Geçici: range_hash
non-zero zorunluluğu (V58 fix) yeterli ama tam kanıt değil.
**Kabul:** 64-depth Merkle proof verify + answer.
**Sorumlu:** ARENA3 (budzero/ZK domain'i).

### V38 — Merkle proof format-only
**Sorun:** `RetrievalResponse.responder_signature` Ed25519 imzası var ama
Merkle proof'u **format kontrolü** dışında doğrulamıyor (STARK verify yok).
**Çözüm:** V37 ile aynı — VerifyMerkle Production gate (MR-3) açılınca.
**Kabul:** ProofEnvelope STARK verify chain'de.
**Sorumlu:** ARENA3 (budzero/ZK domain'i).

**Kritik karar (kullanıcıya):** V37+V38 ikisi de MR-3 (VerifyMerkle) bağımlı.
MR-3 mainnet öncesi zorunlu mu, yoksa V58 non-zero hash + economic slashing
mainnet için yeterli mi?

---

## 3. Açık Yüksek Bulgular (🟡 Mainnet Öncesi)

### V22 — AI Registry domain-separation eksik
ARENA2 P5 ADIM7 (B19) ile kapatıldı (her map'e unique domain prefix). **Teyit
bekliyor** — CI'da V22 status kontrol.

### V23 — NftRegistry luminance overflow
`update_luminance` i128 dönüşümü + negatif kontrol ama u64::MAX üst sınır yok.
**Çözüm:** saturating add + clamp.

### V25 — Snapshot hash kapsam deliği
GAP-2/P2 schema-4 ile kapatıldı (15 alan digest'e eklendi). **Teyit bekliyor.**

### V28 — Executor current_block sapması
`apply_transaction_checked` sırasında `current_block` güncellenmiyor olabilir.
**Çözüm:** Executor audit — block height prop olmalı.

### V30 — EvmChainAdapter no-op (stub)
F10.4 ship edildi ama `verify_receipt_proof` minimal stub. **Tasarım kararı:
mainnet'te bridge kapalı (kullanıcı kararı `f10_before_mainnet` = açık,
ama gerçek RPC client mainnet sonrası).**

### V31 — build_bud_to_eth_claim Burned status yok
`build_bud_to_eth_claim` transfer'in Burned status'unu kontrol etmiyor.
**Çözüm:** BridgeStatus::Burned check ekle.

---

## 4. Mainnet Talimatı Maddeleri — Detaylı Durum + Plan

### Kritik (mainnet konuşulmaz bunlar olmadan)

| # | Madde | Durum | Task 11 Plan |
|---|---|---|---|
| **1** | Bağımsız harici audit | 🔴 Başlamadı | Audit paketi topla + firm teklif (kullanıcı kararı) |
| **2** | Z-B VerifyMerkle 64-depth | 🔴 Production-gated | ARENA3 + budzero ekibi; V37/V38 bağımlı |
| **3** | BLS/PQ HSM vendor-native | 🔴 Mock only | Vendor (YubiHSM/Thales) seçimi + entegrasyon (donanım gerekli) |
| **4** | Relayer güven modeli | 🟡 F10 RFC var | Kullanıcı kararı: permissionless/threshold/single |
| **5** | Fuzzing süresi | 🟡 90s×5 | Nightly 24h koşuyor mu teyit (Fuzz Nightly workflow) |
| **6** | Bug bounty programı | 🟡 Plan var | Immunefi başvuru (F29 augmentation) + SECURITY.md |
| **7** | PoW light-client + legacy | 🟡 Legacy gated | Legacy kaldırma kararı (kullanıcı) |
| **8** | Dependabot birikintisi | ✅ 6 PR kapatıldı | — |
| **9** | Coverage job flake | ✅ Son 2 push yeşil | İzleme |

### Yüksek (Kritik biter bitmez)

| # | Madde | Durum | Plan |
|---|---|---|---|
| **10** | Governance süreci | 🟢 GOVERNANCE.md + V68-V71 kapatıldı | ✅ |
| **11** | PoA kurumsal pilot | 🟡 Config var, donanım test yok | Pilot ortam (kullanıcı/kurumsal partner) |
| **12** | README/badge URL | 🟡 lubosruler -> budlum-xyz | Toplu URL güncelleme |
| **13** | Formal verif/Privacy/AI exec | ⚪ Araştırma | Beket, mainnet sonrası |

### Diğer (süreç)

| # | Madde | Durum |
|---|---|---|
| **14** | Çoklu Arena koordinasyon | 🟢 STATUS_ONLINE aktif |
| **15** | Scope creep kontrolü | 🟢 Talimat §2/§5 |
| **16** | Verifier Registry birleşmemiş | 🟡 Mimari borç |
| **17** | Açık PR review süreci | 🟢 PR triyajı yapıldı |
| **18** | Monolitik vs modüler anlatı | 🟢 Dashboard + modül README'leri |

---

## 5. Sprint Planı (Öncelik Sırası)

### Sprint 11.1 — Kritik bulgu kapanışı (V24, V31)
- **V24:** BridgeState root scope — transfer alanlarını digest'e ekle (ARENA1).
- **V31:** build_bud_to_eth_claim Burned status check (ARENA1).
- **V23:** NftRegistry luminance saturating add (ARENA1/ARENA3).
- **V28:** Executor current_block prop audit (ARENA2).
- **Kapı:** Her biri için negatif test + CI yeşil.

### Sprint 11.2 — ZK proof chain (V37, V38, MR-3)
- **MR-3 VerifyMerkle:** budzero 64-depth soundness + Production gate açma.
- **V37:** answer_challenge → VerifyMerkle entegrasyonu.
- **V38:** ProofEnvelope STARK verify chain.
- **Kapı:** 64-depth proof CI'da zorunlu job.

### Sprint 11.3 — Mainnet operasyonel
- **Madde 1 Audit:** paketle + firm teklif (kullanıcı).
- **Madde 3 HSM:** vendor seçimi + devnet test (donanım gerekli).
- **Madde 6 Bounty:** Immunefi başvuru + SECURITY.md.
- **Madde 9 Operasyonel smoke:** PRODUCTION_RUNBOOK tatbikatı.
- **Madde 11 PoA pilot:** kurumsal partner koordinasyonu.

### Sprint 11.4 — Düşük bulgular + temizlik
- V22 teyit (AI domain-sep).
- V25 teyit (GAP-2 kapanışı).
- V26/V30 tasarım kararları.
- README/badge URL güncelleme (Madde 12).
- 18 Düşük bulgu triyajı.

---

## 6. Kabul Kriterleri (MR-10 için)

- [ ] **MR-1:** 3+ consecutive main push 19/19 yeşil.
- [ ] **MR-3:** VerifyMerkle 64-depth Production gate açık, CI zorunlu job.
- [ ] **MR-5:** Coverage ≥90% (consensus/cross_domain/crypto).
- [ ] **MR-6:** Ceremony gerçek input'larla + F1-F5 flip.
- [ ] **MR-8:** Bug bounty live (Immunefi Medium tier).
- [ ] **MR-9:** PRODUCTION_RUNBOOK tatbikatı kaydedilmiş.
- [ ] **MR-10:** Kullanıcı nihai onayı.
- [ ] **ARENAX:** 0 açık 🔴 Kritik + 0 açık 🟡 Yüksek.

---

## 7. Karar Kapıları (Kullanıcıya Sorulacak)

1. **V37/V38 + MR-3:** VerifyMerkle mainnet öncesi zorunlu mu? (V58 non-zero
   hash + economic slashing yeterli mi?)
2. **Madde 4 Relayer model:** permissionless / threshold / single?
3. **Madde 7 Legacy proof:** tamamen kaldırılsın mı, gerekçesiyle kalsın mı?
4. **Madde 1 Audit:** hangi firm (Spearbit/Trail of Bits/Triumf)?
5. **Madde 3 HSM:** hangi vendor (YubiHSM/Thales/AWS CloudHSM)?
6. **Madde 11 PoA pilot:** kurumsal partner kim?

---

## 8. Riskler

- **MR-3 VerifyMerkle** budzero'nun en zor işi; Gorev 3'te STARK soundness
  kanıtı gerekli. 2-4 hafta tahmin.
- **HSM vendor-native** donanım bağımlı; tedarik + entegrasyon 1-2 ay.
- **Harici audit** firm takvimine bağlı; 4-8 hafta.
- **Ekip koordinasyonu** ARENAX sürekli denetimde; bulgu sayısı artabilir.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
