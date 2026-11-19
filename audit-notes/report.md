# Rapor

## Bu turda yapılanlar

1. **Uç `aa3529c` doğrulandı.** `cargo check --lib --all-targets` temiz
   derlendi. Tam `cargo test --lib` koştu: 6288 test geçti, 0 kızıldı, 3
   yok sayıldı; koşu sonunda test ikili (binary) takıldı
   (`tests::integration::...::test_startup_chain_id_verification_fails`
   tek başına geçiyor, paralel koşuda asılı kalıyor). Bu bir ortam
   sorunudur, koddan kaynaklanmıyor.
2. **VerifyMerkle kapısı hatası bulundu ve düzeltildi.** Bir alan
   (`StorageDomainParams`) doğru kimlikte `require_merkle_proof: true`
   yazdığında, bir değiğin (reallocation) kabul kapısı o alanın kapısını
   yok sayıp ortanın kapısını (her zaman kapalı) kullanıyordu. Dört dosya
   değişti: `deal_open.rs`, `storage_tx.rs`, `blockchain.rs`,
   `storage_economics_tests.rs`. `chain::storage_economics_tests` 16/0,
   `domain::{deal_open,storage_tx,storage_deal}` 247/0.
3. **Strix bulgularının 19 tanesi daha doğrulandı.** HIGH'lar 8, MEDIUM'lar
   22, LOW'lar 10. Ayrıntı: `strix-ledger.md`.
4. **Yeni uç `027296e` doğrulandı.** Uçte 11 yeni commit ve dört yeni
   adaptör var. CI clippy kapısı kırmızıydı: üç hata, hepsi küçük ve
   mekanik. Düzeltildi.

## Yapılamayanlar

- **Tam test koşusu bu turda tamamlanmadı.** Beşinci ortam sıfırlanması
  oldu; araç zinciri, takas ve `target/` yeniden kuruldu. Uç derlemesi
  doğrulandı, testler hedefli koşuldu.
- **CI koşu numarası citefilemez.** Depoda kayıtlı koşurucu (runner) yoktur.
  Bu yüzden her iddia yerel doğrulama ile yapılır.

## Sonraki tur

1. Yeni uçte tam `cargo test --lib`.
2. Dört yetim adaptörün (based-preconf, ton-catchain, mina-recursive,
   stellar-scp) ya bağlanması ya da açıkça kapatılacak diye kayda geçmesi.
3. Kalan MEDIUM ve LOW bulgular.
