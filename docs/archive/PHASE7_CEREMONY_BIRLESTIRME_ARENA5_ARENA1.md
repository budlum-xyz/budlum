# Phase 7 — Ceremony Birleştirme Planı (ARENA5 + ARENA1)

**Tarih:** 2026-07-15  
**ARENA5:** Plan + Template + Dokümantasyon  
**ARENA1:** Kod + Test + Altyapı  
**HEAD:** `origin/main` = `dc073c6` + CI fix `server.rs`  
**Durum:** Aktif Koordinasyon

---

## 1. Birleştirme Matrisi

| Görev | ARENA5 Katkısı | ARENA1 Katkısı | Durum |
|-------|----------------|----------------|-------|
| **7.1 Genesis keys** | `MAINNET_GENESIS_CEREMONY.md` §3-4 template | Genesis hash doğrulama scripti | ⏳ Kullanıcı keys |
| **7.2 Bootnodes** | `PHASE7_CEREMONY_PLAN.md` §3.2 prosedür | `config/mainnet.toml` gerçek multiaddr | ⏳ Altyapı |
| **7.3 HSM ceremony** | `M5_VERIFYMERKLE_RAPOR_ARENA5.md` analiz | `src/crypto/pkcs11.rs` vendor-native | 🟡 Config var |
| **7.4 Hash freeze** | `MAINNET_GENESIS_CEREMONY.md` §6 prosedür | Hash hesapla + PRODUCTION_RUNBOOK §8 | ⏳ 7.1 sonrası |
| **7.5 Launch checklist** | `PHASE7_CEREMONY_PLAN.md` §3.5 checklist | CI yeşil + testler + smoke | 🔴 CI fix sonrası |

## 2. Ortak Ceremony Checklist (ARENA5 + ARENA1)

### Pre-launch (T-7 gün)
- [ ] **CI fix:** `src/rpc/server.rs` kapanış `}` eklendi → CI yeşil (ARENA5)
- [ ] **Genesis keys:** Kullanıcı gerçek Ed25519 + BLS + PQ anahtarlarını üretti (Kullanıcı)
- [ ] **Treasury allocation:** 5 havuz adresi belirlendi (Kullanıcı)
- [ ] **Bootnodes:** 3+ sunucu çalışıyor, multiaddr kaydedildi (ARENA1 + Kullanıcı)
- [ ] **DNS seeds:** 2+ `_dnsaddr` TXT record oluşturuldu (Kullanıcı)
- [ ] **Snapshot round-trip:** `StateSnapshotV2` BNS/NFT/Hub/Marketplace restore test geçti (ARENA1 + ARENA3)
- [ ] **Byzantine stress test:** `test_chaos_v2_ultimate_byzantine_recovery` yeşil (ARENA1)
- [ ] **VerifyMerkle gate:** `is_experimental() = true` — kapalı, fail-closed (ARENA2/ARENA3)
- [ ] **THREAT_MODEL §3.2:** "VerifyMerkle kapalı, Faz 3 interim" notu eklendi (ARENA5)
- [ ] **README "30/31 opcode":** Dürüst düzeltme yapıldı (ARENA5 önerisi)

### Launch günü (T-0)
- [ ] `mainnet-genesis.json` finalize edildi (Kullanıcı + ARENA5 template)
- [ ] Genesis hash hesaplandı: `sha256sum config/mainnet-genesis.json` → `PRODUCTION_RUNBOOK.md` §8.2
- [ ] `mainnet.toml` `ceremony_status = "frozen"` yapıldı
- [ ] 4 validator node başlatıldı (ARENA1 altyapı)
- [ ] İlk BLS prevote/precommit başarılı
- [ ] İlk blok üretildi (`bud_blockNumber` → 1)
- [ ] RPC health check OK (`bud_health`)
- [ ] Prometheus metrics akıyor
- [ ] P2P peer discovery çalışıyor (3+ peer connected)

### Post-launch (T+1 hafta)
- [ ] Archive node backup drill (ARENA2)
- [ ] Incident response runbook testi
- [ ] Bug bounty duyurusu (immunefi)
- [ ] VerifyMerkle 64-depth debug devam (ARENA2/ARENA3)
- [ ] Phase 5 Kapı A-G atomik PR'lar (ARENA1 + ARENA6)

## 3. ARENA1'e Spesifik Sorular

1. **Genesis hash script:** `mainnet-genesis.json` → SHA256 hash hesaplayan ve `PRODUCTION_RUNBOOK.md`'ye otomatik yazan bir script var mı? Yoksa ARENA5 mi yazsın?

2. **Bootnode validation:** `mainnet.toml`'daki bootnodes'un gerçek olup olmadığını doğrulayan bir test var mı? (Dummy peer ID `12D3KooWDummyBootstrap` pattern match ile reddetme)

3. **Validator set minimum:** Mainnet için minimum validator sayısı ne? 4 mü, N-of-M mi? `mainnet-genesis.json`'da kaç validator olmalı?

4. **Ceremony air-gap:** Genesis keys ceremony air-gap makinede mi yapılacak? Varsa prosedürü `MAINNET_GENESIS_CEREMONY.md`'ye ekleyelim.

5. **Hub UI integration:** Prototip kullanıcı talimatıyla repodan kaldırıldı (`845ba5c`, 2026-07-16); kaynak dal: `arena/019f6714-budlum`. Mainnet launch ile yayınlanacak mı? Karar: kullanıcı. Yayınlanacaksa domain/hosting planı?

## 4. Risk Matrisi (Güncelleme)

| Risk | Olasılık | Etki | Azaltma | Sorumlu |
|------|----------|------|---------|---------|
| server.rs unclosed delimiter | ✅ Çözüldü | Yüksek | 1-satır fix (ARENA5) | ARENA5 |
| HSM donanım yok | Orta | Yüksek | Ed25519-only launch | Kullanıcı |
| VerifyMerkle uzun kırmızı | Orta | Orta | Kapalı launch (M5 rapor) | ARENA2/3 |
| Genesis key sızıntısı | Düşük | Kritik | HSM air-gap | Kullanıcı |
| Bootnode arızası | Düşük | Orta | 3+ coğrafi dağılım | ARENA1 |
| Phase 5 relayer placeholder | Yüksek | Düşük | Post-launch activation | ARENA1 |

## 5. Doküman Cross-Reference

| Doküman | Konum | Sahip |
|---------|-------|-------|
| Phase 7 Ceremony Plan | `docs/PHASE7_CEREMONY_PLAN.md` | ARENA5 |
| M5 VerifyMerkle Rapor | `docs/M5_VERIFYMERKLE_RAPOR_ARENA5.md` | ARENA5 |
| Genesis Ceremony Template | `docs/MAINNET_GENESIS_CEREMONY.md` | ARENA5 |
| CI Root Cause Analysis | `docs/CI_ROOT_CAUSE_ANALYSIS_ARENA5.md` | ARENA5 |
| Agent Audit Report | `docs/AGENT_AUDIT_REPORT.md` | ARENA1 |
| Hub UI Prototype | kaldırıldı (`845ba5c`, kullanıcı talimatı); dal: `arena/019f6714-budlum` | ARENA1 |
| Phase 5 Denetim | `docs/PHASE5_ARENA6_DENETIM_2026-07-15.md` | ARENA6 |
| Yeni Aşamalar Plan | `docs/YENI_ASAMALAR_PLAN_ARENA3_2026-07-16.md` | ARENA3 |
| Mainnet Readiness | `docs/MAINNET_READINESS.md` | ARENA1 |
| Threat Model | `docs/THREAT_MODEL.md` | ARENA3 |

---

**Force-push YASAK. Workflow push YASAK.**  
Co-authored-by: ARENA5 + ARENA1 (koordinasyon)
