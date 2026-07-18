# Phase 8.9 — Derin Kod Denetimi & Phase 6/7 Kapanış Matrisi (ARENA3)

**Tarih:** 2026-07-16  
**HEAD:** `c4b94db` (CI 8/8 yeşil)  
**Denetçi:** ARENA3  
**Kapsam:** Yeni modüllerde derin güvenlik denetimi, çalışmayan kod envanteri, ceremony belge konsolidasyonu, Phase 6/7 iddia-vs-kanıt matrisi

---

## 1. Derin Kod Denetimi — Modül Bazında

### 1.1 BNS Registry (`src/bns/`) — 262 satır
| Kontrol | Sonuç | Detay |
|---------|-------|-------|
| unwrap/expect/panic | ✅ TEMİZ | 0 adet |
| Owner verification | ✅ SAĞLAM | register_subdomain, set_content, set_storage hepsi caller==owner kontrolü yapıyor |
| Expiry check | ✅ SAĞLAM | resolve, resolve_full, resolve_content, set_storage hepsi expiry kontrol ediyor |
| Name validation | ✅ SAĞLAM | 3-32 karakter sınırı |
| Integer safety | ✅ TEMİZ | calculate_cost çarpma-only, overflow riski yok |
| Anti-spam | 🟡 ZAYIF | `base_cost=100` token, ama register için fee deduction EXECUTOR'da değil — register doğrudan RPC'den çağrılırsa maliyet yok |
| Storage binding | ✅ SAĞLAM | storage_root + storage_domain_id + storage_root_height üçlüsü atomik set |

### 1.2 NFT Registry (`src/nft/`) — 101 satır
| Kontrol | Sonuç | Detay |
|---------|-------|-------|
| unwrap/expect/panic | ✅ TEMİZ | 0 adet |
| Owner verification | ✅ SAĞLAM | transfer, burn owner check correct |
| Integer safety | ✅ SAĞLAM | update_luminance: i128 overflow korumalı, min 0 |
| ID uniqueness | ✅ SAĞLAM | next_id monotonik artar, duplicate imkansız |
| Tag injection | ✅ TEMİZ | add_tag idempotent (contains check) |
| Burn cleanup | ✅ SAĞLAM | ownership map'ten de siliniyor |

### 1.3 Marketplace (`src/marketplace/`) — 55 satır
| Kontrol | Sonuç | Detay |
|---------|-------|-------|
| unwrap/expect/panic | ✅ TEMİZ | 0 adet |
| Owner verification | ✅ SAĞLAM | close_offer: seller==caller |
| Error type | 🟡 ZAYIF | `close_offer` String döndürüyor, proper error type değil |
| Zero-price check | 🔴 EKSİK | `create_offer` minimum price kontrolü YOK — bedava teklif açılabilir |
| Offer uniqueness | ✅ SAĞLAM | next_offer_id monotonik |

### 1.4 Hub (`src/hub/`) — 75 satır
| Kontrol | Sonuç | Detay |
|---------|-------|-------|
| unwrap/expect/panic | ✅ TEMİZ | 0 adet |
| Developer verification | ✅ SAĞLAM | update_app: developer==caller |
| **verify_app access control** | 🔴 KRİTİK | **HERKES herhangi bir app'i verify edebiliyor!** `verify_app` hiçbir caller kontrolü yapmıyor — admin/DAO gate YOK |
| Anti-spam | 🟡 ZAYIF | register_app permissionless, fee yok — spam riski |
| Registration cost | 🟡 ZAYIF | Ücretsiz kayıt — sybil saldırılarına açık |

### 1.5 Gateway (`src/gateway/`) — 34 satır
| Kontrol | Sonuç | Detay |
|---------|-------|-------|
| unwrap/expect/panic | ✅ TEMİZ | 0 adet |
| BNS resolution | ✅ DOĞRU | `chain.bns_resolve_content()` çağrısı doğru |
| Storage fetch | 🔴 STUB | `fetch_name_content` HER ZAMAN `Err(...)` döndürüyor — Bitswap entegrasyonu pending |
| Error handling | ✅ SAĞLAM | `ok_or_else` ile düzgün hata mesajı |

### 1.6 Relayer Worker (`src/relayer/`) — 100 satır
| Kontrol | Sonuç | Detay |
|---------|-------|-------|
| unwrap/expect/panic | ✅ TEMİZ | 0 adet |
| Block polling | ✅ SAĞLAM | last_height→current_height döngüsü doğru |
| To-address | 🔴 STUB | `Address::zero()` kullanılıyor |
| Signature | 🔴 STUB | `result_tx` oluşturuluyor ama İMZALANMIYOR — validation'da fail eder |
| Receipt proof | 🔴 STUB | `vec![1,2,3]` mock proof |
| tx_hash | 🔴 STUB | `[0xEE; 32]` mock hash |

---

## 2. Executor Güvenlik Denetimi (Phase 6 tx tipleri)

### 2.1 NftBoost (SocialFi)
| Kontrol | Sonuç |
|---------|-------|
| NFT varlık kontrolü | ✅ `get_nft(nft_id).ok_or(...)` |
| Bakiye kontrolü | ✅ `booster.balance < amount + fee` |
| saturating math | ✅ Tüm çıkarma/toplama işlemleri |
| Creator reward | ✅ %4 BUD share + %16 creator share |
| Nonce güncelleme | ✅ |

### 2.2 NftUpdateLight
| Kontrol | Sonuç |
|---------|-------|
| **Gerçek implementasyon** | 🔴 STUB — `let _ = (nft_id, delta_mcd)` hiçbir şey yapmıyor |
| Fee deduction | ✅ |
| Nonce güncelleme | ✅ |

### 2.3 NftTag
| Kontrol | Sonuç |
|---------|-------|
| Tag ekleme | ✅ `nft_registry.add_tag()` çağrısı |
| Fee + nonce | ✅ |

### 2.4 AiOfferData / AiPurchaseData
| Kontrol | Sonuç |
|---------|-------|
| Offer creation | ✅ `marketplace.create_offer()` |
| **H2 Fix (race condition)** | ✅ Önce close_offer, sonra payment |
| Bakiye kontrolü | ✅ `total_cost = price + fee` |
| Seller payment | ✅ `seller.balance += offer.price` |

### 2.5 HubRegisterApp
| Kontrol | Sonuç |
|---------|-------|
| Permissionless | ✅ Bilinçli — herkes dApp kaydedebilir |
| Spam koruması | 🟡 Fee dışında yok |

### 2.6 RelayerResult
| Kontrol | Sonuç |
|---------|-------|
| Empty proof check | ✅ `receipt_proof.is_empty()` reddediliyor |
| Kriptografik doğrulama | 🔴 YOK — sadece boş kontrol, gerçek Merkle/state proof verify YOK |

---

## 3. StateSnapshot Persistence Denetimi

| Alan | Snapshot V2'de | from_snapshot_v2 restore |
|------|---------------|------------------------|
| bns_registry | ✅ `Option<BnsRegistry>` #[serde(default)] | ✅ `unwrap_or_default()` |
| nft_registry | ✅ `Option<NftRegistry>` #[serde(default)] | ✅ `unwrap_or_default()` |
| marketplace | ✅ `Option<MarketplaceRegistry>` #[serde(default)] | ✅ `unwrap_or_default()` |
| hub | ✅ `Option<HubRegistry>` #[serde(default)] | ✅ `unwrap_or_default()` |

**Sonuç:** ✅ Tüm yeni alanlar kalıcı — restart sonrası veri kaybı YOK.

---

## 4. Transaction Signing Hash Coverage

| Tx Tipi | type_byte | signing_hash | is_valid | Executor |
|---------|-----------|-------------|----------|----------|
| Transfer | 0 | ✅ | ✅ | ✅ |
| Stake | 1 | ✅ | ✅ | ✅ |
| Unstake | 2 | ✅ | ✅ | ✅ |
| Vote | 3 | ✅ | ✅ | ✅ |
| ContractCall | 4 | ✅ | ✅ | ✅ |
| BnsRegister | 5 | ✅ | ✅ | ✅ |
| BnsSetContent | 6 | ✅ | ✅ | ✅ |
| BnsRegisterSubdomain | 7 | ✅ | ✅ | ✅ |
| BnsSetStorage | 8 | ✅ | ✅ | ✅ |
| NftMint | 9 | ✅ | ✅ | ✅ |
| NftTransfer | 10 | ✅ | ✅ | ✅ |
| NftBurn | 11 | ✅ | ✅ | ✅ |
| NftBoost | 12 | ✅ | ✅ | ✅ |
| NftUpdateLight | 13 | ✅ | ✅ ✅ (stub) |
| NftTag | 14 | ✅ | ✅ | ✅ |
| UniversalRelay | 15 | ✅ | ✅ | ✅ |
| RelayerResult | 16 | ✅ | ✅ | ✅ (stub) |
| AiOfferData | 17 | ✅ | ✅ | ✅ |
| AiPurchaseData | 18 | ✅ | ✅ | ✅ |
| HubRegisterApp | 19 | ✅ | ✅ | ✅ |

**Sonuç:** ✅ 20 varyantın tamamı kapsanmış.

---

## 5. Çalışmayan Kod Envanteri

| # | Dosya | Durum | Risk | Açıklama |
|---|-------|-------|------|----------|
| C1 | `src/gateway/service.rs:26` | 🔴 STUB | Yüksek | `fetch_name_content` her zaman Err döndürüyor |
| C2 | `src/relayer/worker.rs:80-95` | 🔴 STUB | Orta | `Address::zero()`, imzasız tx, mock proof |
| C3 | `src/execution/executor.rs:361-366` | 🟡 STUB | Düşük | NftUpdateLight stub (`let _ = ...`) |
| C4 | `src/execution/executor.rs:378-397` | 🟡 STUB | Orta | RelayerResult kriptografik doğrulama yok |
| C5 | `src/hub/mod.rs:65-68` | 🔴 AÇIK | Yüksek | verify_app access control YOK |
| C6 | `src/marketplace/mod.rs:28` | 🟡 AÇIK | Düşük | create_offer zero-price check YOK |

---

## 6. Ceremony Belge Konsolidasyonu

**Mevcut durum:** 4 ayrı ceremony belgesi:
1. `docs/MAINNET_GENESIS_CEREMONY.md` (7902 byte)
2. `docs/PHASE7_CEREMONY_BIRLESTIRME_ARENA5_ARENA1.md` (5138 byte)
3. `docs/PHASE7_CEREMONY_PLAN.md` (8502 byte)
4. `docs/operations/MAINNET_GENESIS_CEREMONY.md` (5098 byte)

**Toplam:** ~26 KB, 4 dosyada dağınık. **Öneri:** Tek `docs/operations/MAINNET_GENESIS_CEREMONY.md` altında birleştirilmeli.

---

## 7. Phase 6/7 İddia-vs-Kanıt Matrisi

| İddia | Kanıt | Hüküm |
|-------|-------|-------|
| "BNS Phase 6 tamamlandı" | registry + types + executor + RPC + lifecycle testleri | ✅ KOD+TEST |
| "SocialFi NFT posts" | NftMint/NftTransfer/NftBurn/NftBoost/NftTag executor'da | ✅ KOD |
| "NftUpdateLight çalışıyor" | `let _ = (nft_id, delta_mcd)` stub | ❌ STUB |
| "Gateway BNS→content çözümleme" | Her zaman Err döndürüyor | ❌ STUB |
| "Relayer EVM proofs doğrulama" | Mock proof, imzasız tx | ❌ STUB |
| "Hub dApp registration" | register_app çalışıyor, verify_app access control YOK | 🟡 KISMİ |
| "AI Marketplace" | create_offer + purchase (H2 fixed) | ✅ KOD+TEST |
| "Ceremony hazır" | 4 belge dağınık, bootnodes placeholder | 🟡 KISMİ |
| "StateSnapshot persistence" | bns/nft/marketplace/hub hepsi V2'de | ✅ KOD |

---

## 8. Açık Güvenlik Bulguları (Öncelik Sıralı)

| # | Bulgu | Şiddet | Modül | Önerilen Fix |
|---|-------|--------|-------|-------------|
| H3 | verify_app access control YOK | 🔴 HIGH | hub/mod.rs:65 | caller==app.developer veya DAO gate ekle |
| H4 | Gateway her zaman Err | 🔴 HIGH | gateway/service.rs:26 | Bitswap P2P fetch entegre et |
| M3 | Marketplace zero-price | 🟡 MEDIUM | marketplace/mod.rs:28 | `if price == 0 { return Err }` |
| M4 | BNS register fee check Executor'da yok | 🟡 MEDIUM | executor.rs + bns/ | BnsRegister kolunda fee + cost kontrolü ekle |
| M5 | Hub spam koruması yok | 🟡 MEDIUM | hub/mod.rs:20 | Minimum registration fee ekle |
| L1 | RelayerResult kriptografik doğrulama yok | 🟡 LOW | executor.rs:378 | Merkle proof verify ekle |
| L2 | NftUpdateLight stub | 🟡 LOW | executor.rs:361 | Gerçek luminance update implemente et |

---

## 9. Sonuç

**Phase 6/7 genel durumu:** BNS ve NFT çekirdeği sağlam, Marketplace H2 fixli, StateSnapshot persistence doğru. Ama Gateway stub, RelayerWorker stub, NftUpdateLight stub, Hub verify_app açık. Bu boşluklar kapanmadan "Phase 6 tamamlandı" iddiası **dürüst değil**.

**Dürüst cümle:** Phase 6 (BNS/SocialFi/Gateway/Relayer) büyük ölçüde kodlanmış, ancak Gateway Bitswap entegrasyonu, Relayer gerçek kriptografik doğrulama, Hub access control ve NftUpdateLight implementasyonu hâlâ stub/eksik. Phase 7 ceremony belgeleri dağınık (4 dosya) — konsolidasyon gerekli.
