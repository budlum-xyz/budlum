# B.U.D. — Broad Universal Database (modül README'si)

**Modül-ayrımı kuralı gereği B.U.D.'un kendi README'sidir.**
Kök `README.md` yalnızca dashboard'dur; olgunluk/risk uyarıları burada yaşar.

## Durum

- **Olgunluk:** devnet-only. Mainnet'e dahil edilip edilmeyeceği ayrı karar.
- **Kod konumu:** `src/storage/` (manifest, deal, params), RPC uçları `src/rpc/api.rs` (`bud_storage*`),
  E2E testleri `src/tests/bud_e2e.rs`.
- **RPC yüzeyi:** `bud_storageRegisterManifest`, `bud_storageOpenDeal`,
  `bud_storageGetManifest`, `bud_storageGetDealsByManifest`, `bud_storageGetDealsByShard`,
  `bud_storageOpenChallenge`, `bud_storageAnswerChallenge`,
  `bud_storageGetOutcome`, `bud_storageGetEconomicsSummary`,
  `bud_storageGetEconomicsEvents`, `bud_storageGetOperatorEconomics`.
- **Veri egemenliği kuralı:** whitelist/admin/pause/freeze hook'u YOK; her RPC her node
  tarafından sunulabilir. Bu kural CI'daki 9 invariant ile kilitli.

## Olgunluk uyarıları (kök dashboard'a taşınmadan burada kalır)

1. **Sahte-yeşil riski:** `RetrievalChallenge` gerçek Proof-of-Storage değildir —
   yanıt yalnız `range_hash` kabul eder (bkz. `api.rs` notu); operatör tam veri yerine
   yalnız istenen byte-range'i saklayarak gate'i geçebilir. `bud_storageGetOutcome`
   bu nedenle her yanıtta `proofKind` / `proof_kind = "interim_availability_only"` döndürür. Tam
   kanıt BudZKVM `VerifyMerkle` 64-derinlik Production-gate'ine bağlıdır (kapalı).
2. **İzin/consent katmanı yok:** manifest ve deal bilgisi tamamen açıktır;
   `AccessGrant` kavramı izin katmanında tasarlanacaktır
   (hard-enforcement hedefli — egemenlik kuralı soft enforcement'ı eler).
3. **`ContentManifest` owner taşır, ama zorunlu değil.** F01 ile `owner` alanı
   eklendi ve `manifest_id` hesabı owner'ı kapsıyor (alanlar:
   `manifest_id/owner/total_size/shard_count/shards`). Ancak `from_shards()`
   owner'ı zero-address ile başlatır ve gerçek sahip `with_owner()` ile ayrıca
   set edilir. Bu çağrı atlanırsa manifest "sahipsiz" olarak kaydedilir ve aynı
   içeriği yükleyen iki farklı kullanıcı aynı `manifest_id`'yi üretir. Kayıt
   yolunda owner'ın zorunlu kılınması izin katmanının işi.
4. **Replikalar ayırt edilemez (outsourcing/Sybil).** `ContentId` düz içerik
   hash'i olduğu için aynı shard'ı saklayan N operatör bayt-bayt aynı veriyi
   tutar. Tek fiziksel kopya N deal'i karşılayabilir ve tek makine N kimlikle
   N ödül toplayabilir. Filecoin'in PoRep'i bunu replika-başına kodlama ile
   çözer; B.U.D.'da böyle bir kodlama **yok**. Ayrıntı ve yol haritası:
   `docs/BUD_STORAGE_ROADMAP.md`.

5. **Yedeklilik erasure coding değil, replikasyon.** `ShardRef` yalnız
   `(index, shard_id, size)` taşır; parity shard kavramı yok. Dayanıklılık
   replika başına tam kopya maliyetiyle geliyor ve bir operatör slash
   edildiğinde kaybolan yedekliliği onaran bir yol tanımlı değil.

6. **Ekonomi yönü sağlayıcıdır:** operatörler saklama karşılığı ödeme alır; AI'nin
   erişim için ödediği "tüketici erişim" ekonomisi ayrı bir katman
   olarak tasarlanır.
7. **Slashed-bond akışı:** devnet ara muhasebesinde missed-challenge sonrası
   `slashedBondDisposition = "burn_from_operator_liquid_balance_best_effort"`
   olarak RPC'de görünür; bu final mainnet tokenomics kararı değildir.

## Test suite

- **Kapı:** `B.U.D. E2E Invariants (9/9 isim-kilitli)` CI job'u (`ci.yml`) —
  `cargo test --lib bud_e2e` + `scripts/check-bud-e2e.sh` isim kanaryası
  (vacuous-gate koruması: bir invariant silinir/yeniden adlandırılırsa kapı FAIL).
- **Kapsam:** 9 modül-bağımsızlık invariantı + 4 E2E akış (13 zorunlu test),
  buna entropy-seçilmiş challenge aralığına karşı kötü niyetli cached-range
  operatör senaryosu dahildir. Registry unit testleri ayrıca `Slashed →
  ReallocationPending → ActiveReplacement` ve `UnderReplicated` repair-state
  geçişlerini kilitler.
- Birim testleri (manifest doğrulama, chunk params, prune/slash idempotensi)
  Core lib suite içinde koşar (`cargo test --lib`; toplam sayı rozeti 755 lib,
  2026-07-18).

## Yol haritası işaretleri

- İzin katmanı: `AccessGrant` + `AccessRevocation` + sahip-imzalı provenance
  (`StorageCommitment`) + -2 key-wrapping (hard enforcement).
- Zorunlu entegrasyon: `AiInferenceRequest.input_ref` bir
  `DataAsset`'e işaret ediyorsa AiVerifier grant kontrolü OLMADAN hesaplayamaz.
- Tam-PoS (Merkle-64) gate'i kapanmadan "veri bütünlüğü kanıtlandı" iddiası
  kurulamaz — sahte-yeşil uyarısı o güne kadar bu README'de kalır.
