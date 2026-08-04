# B.U.D.: Broad Universal Database (modül README'si)

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

1. **Sahte-yeşil riski:** `RetrievalChallenge` gerçek Proof-of-Storage değildir,
   yanıt yalnız `range_hash` kabul eder (bkz. `api.rs` notu); operatör tam veri yerine
   yalnız istenen byte-range'i saklayarak gate'i geçebilir. `bud_storageGetOutcome`
   bu nedenle her yanıtta `proofKind` / `proof_kind = "interim_availability_only"` döndürür. Tam
   kanıt BudZKVM `VerifyMerkle` 64-derinlik Production-gate'ine bağlıdır (kapalı).
2. **İzin/consent katmanı yok:** manifest ve deal bilgisi tamamen açıktır;
   `AccessGrant` kavramı izin katmanında tasarlanacaktır
   (hard-enforcement hedefli, egemenlik kuralı soft enforcement'ı eler).
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

5. **Erasure coding var, parity üretimi üretim akışına bağlı değil.**
   `ShardRef` artık `kind` (`Data` / `Parity`) taşıyor ve `ContentManifest`
   bir `ErasureScheme { k, n }` taşıyor; `src/storage/erasure.rs` GF(2^8)
   üzerinde gerçek bir Reed-Solomon kodlayıcıdır ve `(4,6)` bir kodun on beş
   iki-kayıp deseninin tamamını test eder.

   Açık kalan iki nokta var ve ikisi de dayanıklılık vaadine dokunur.

   Birincisi: parity baytlarını **kimse hesaplamıyor**. `encode_object` ve
   `to_manifest` üretim ağacında hiçbir yerden çağrılmıyor; manifest zincire
   istemciden hazır geliyor. Modülün başındaki `WIRING: unwired` işareti bunu
   söylüyor.

   İkincisi, ve daha derini: zincir shard **baytlarını hiç görmez**, yalnızca
   hash'lerini görür. `validate_untrusted` sayıların tutarlılığını denetler
   (Data sayısı `k`, Parity sayısı `n - k`), ama bir parity shard'ın gerçekten
   doğru parity olup olmadığını denetleyemez. Rastgele altı bayt dizisiyle
   `(k=4, n=6)` beyan eden bir manifest bugün kabul edilir; hata ancak
   gerçekten kayıp olduğunda, yani iş işten geçtikten sonra görünür.

   Bu ikinci nokta bir eksik satır değil, bir tasarım kalemi. Ethereum'un
   danksharding'i aynı soruyla karşılaştı ve iki yol tanımladı: hile kanıtı
   (fraud proof), yani baytları indiren bir tarafın yanlış kodlamayı
   ispatlaması; ya da polinom taahhüdü (KZG) / FRI, yani kodlamanın doğruluğunu
   veriyi indirmeden ispatlayan bir kanıt. B.U.D.'un mevcut challenge
   mekanizması birinciye yakın duruyor: `RetrievalChallenge` zaten bir bayt
   aralığı isteyip hash'ini doğruluyor.

   Onarım tarafı ölçüldü ve hesap doğru: `objects_needing_repair` payda olarak
   ayrı shard sayısını alıyor, replika sayısını değil, ve `k`'nin altına düşmüş
   nesneleri onarım kuyruğuna değil alarm listesine koyuyor. Ancak bu
   fonksiyonları çağıran bir üretim yolu ve bir RPC ucu henüz yok.

6. **Ekonomi yönü sağlayıcıdır:** operatörler saklama karşılığı ödeme alır; AI'nin
   erişim için ödediği "tüketici erişim" ekonomisi ayrı bir katman
   olarak tasarlanır.
7. **Slashed-bond akışı:** devnet ara muhasebesinde missed-challenge sonrası
   `slashedBondDisposition = "burn_from_operator_liquid_balance_best_effort"`
   olarak RPC'de görünür; bu final mainnet tokenomics kararı değildir.

## Test suite

- **Kapı:** `B.U.D. E2E Invariants (9/9 isim-kilitli)` CI job'u (`ci.yml`) -
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
  kurulamaz, sahte-yeşil uyarısı o güne kadar bu README'de kalır.
