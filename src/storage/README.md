# B.U.D. — Broad Universal Database (modül README'si)

**Bu dosya,  Bölüm 4 modül-ayrımı kuralı gereği B.U.D.'un kendi README'sidir.**
Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları burada yaşar.

## Durum

- **Olgunluk:** devnet-only. Mainnet'e dahil edilip edilmeyeceği ayrı karar.
- **Kod konumu:** `src/storage/` (manifest, deal, params), RPC uçları `src/rpc/api.rs` (`bud_storage*`),
  E2E testleri `src/tests/bud_e2e.rs`.
- **RPC yüzeyi (9 uç):** `bud_storageRegisterManifest`, `bud_storageOpenDeal`,
  `bud_storageGetManifest`, `bud_storageGetDealsByManifest`, `bud_storageGetDealsByShard`,
  `bud_storageOpenChallenge`, `bud_storageAnswerChallenge`,
  `bud_storageGetEconomicsSummary`, `bud_storageGetEconomicsEvents`.
- **Veri egemenliği kuralı:** whitelist/admin/pause/freeze hook'u YOK; her RPC her node
  tarafından sunulabilir. Bu kural CI'daki 9 invariant ile kilitli.

## Olgunluk uyarıları (kök dashboard'a taşınmadan burada kalır)

1. **Sahte-yeşil riski:** `RetrievalChallenge` gerçek Proof-of-Storage değildir —
   yanıt yalnız `range_hash` kabul eder (bkz. `api.rs` notu); operatör tam veri yerine
   yalnız istenen byte-range'i saklayarak gate'i geçebilir. Tam kanıt BudZKVM
   `VerifyMerkle` 64-derinlik Production-gate'ine bağlıdır (kapalı).
2. **İzin/consent katmanı yok:** manifest ve deal bilgisi tamamen açıktır;
   `AccessGrant` kavramı  Bölüm 2 kapsamında tasarlanacaktır
   (hard-enforcement hedefli — egemenlik kuralı soft enforcement'ı eler).
3. **`ContentManifest` owner alanı içermez** (2026-07-18 kod doğrulaması:
   alanlar yalnız `manifest_id/total_size/shard_count/shards`). Sahiplik,
    izin katmanında eklenecek.
4. **Ekonomi yönü sağlayıcıdır:** operatörler saklama karşılığı ödeme alır; AI'nin
   erişim için ödediği "tüketici erişim" ekonomisi  Bölüm 2'de ayrı katman
   olarak tasarlanır.

## Test suite

- **Kapı:** `B.U.D. E2E Invariants (9/9 isim-kilitli)` CI job'u (`ci.yml`) —
  `cargo test --lib bud_e2e` + `scripts/check-bud-e2e.sh` isim kanaryası
  (vacuous-gate koruması: bir invariant silinir/yeniden adlandırılırsa kapı FAIL).
- **Kapsam:** 9 ekip-bağımsızlık invariantı + 3 aktör-akış E2E (12 zorunlu test).
- Birim testleri (manifest doğrulama, chunk params, prune/slash idempotensi)
  Core lib suite içinde koşar (`cargo test --lib`; toplam sayı rozeti 755 lib,
  2026-07-18).

## Yol haritası işaretleri

-  Bölüm 2: `AccessGrant` + `AccessRevocation` + sahip-imzalı provenance
  (`StorageCommitment`) + -2 key-wrapping (hard enforcement).
-  Bölüm 2 zorunlu entegrasyonu: `AiInferenceRequest.input_ref` bir
  `DataAsset`'e işaret ediyorsa AiVerifier grant kontrolü OLMADAN hesaplayamaz.
- Tam-PoS (Merkle-64) gate'i kapanmadan "veri bütünlüğü kanıtlandı" iddiası
  kurulamaz — sahte-yeşil uyarısı o güne kadar bu README'de kalır.
