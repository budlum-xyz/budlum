# CI GENİŞLETME — Eklenecek Kod/Test Kontrolleri

Bu doküman sadece **kod ve CI job'ı** ile eklenecek kontrolleri kapsar
(branch protection, CODEOWNERS gibi repo ayarları hariç — onlar ayrı
konu). Her madde: ne eklenecek, neden gerekli, nasıl eklenir, kabul
kriteri.

---

## Determinizm

### 1. Genesis reproducibility check
**Neden:** Sıfırdan yapılan iki ayrı build aynı genesis hash'ini
üretmiyorsa, ağ başlangıcından itibaren fork riski var.
**Ne eklenecek:** CI'da temiz bir ortamda iki kez `cargo run -- genesis
--config <aynı config>` çalıştır, çıkan state hash'lerini karşılaştır.
**Nasıl:** Yeni bir job, `ci.yml` içine — build cache'siz iki matrix
entry, sonunda hash diff.
**Kabul kriteri:** Job CI'da zorunlu, iki hash birebir eşleşiyor.

### 2. Cross-platform determinism matrix
**Neden:** Node'lar farklı donanımda (x86/ARM) veya farklı OS'de
(Linux/macOS) farklı state hash'ine ulaşırsa, gerçek ağda fork
riski var — özellikle floating point veya HashMap iterasyon sırası
gibi ince farklar.
**Ne eklenecek:** Mevcut `Budlum Core` job'ını GitHub Actions
matrix'iyle en az `ubuntu-latest` + `macos-latest` üzerinde çalıştır,
aynı test setinin state hash çıktısını karşılaştır.
**Nasıl:**
```yaml
strategy:
  matrix:
    os: [ubuntu-latest, macos-latest]
runs-on: ${{ matrix.os }}
```
**Kabul kriteri:** İki platformda da aynı final state hash.

### 3. Migration/upgrade path testi
**Neden:** `ConsensusStateV2` gibi migration'lar veri bozmadan
çalışmalı; mainnet'te canlı veri üzerinde migration hata kaldırmaz.
**Ne eklenecek:** Eski format bir state snapshot'ı fixture olarak
tut, `--migrate-v2` komutunu bu fixture üzerinde çalıştır, migration
sonrası beklenen alanların (bakiyeler, nonce'lar, validator seti)
kaybolmadığını assert et.
**Nasıl:** `src/tests/migration_v2.rs` altında yeni entegrasyon testi,
CI'da ayrı adım olarak koş.
**Kabul kriteri:** Test fixture'ı repo'da, CI'da zorunlu, geçiyor.

---

## Kod güvenliği araçları

### 4. Miri (undefined behavior denetimi)
**Neden:** Mevcut `geiger` sadece unsafe blok *sayısını* sayıyor,
içindeki mantığı denetlemiyor. Miri gerçek UB'yi (use-after-free,
uninitialized memory, data race) çalışma zamanında yakalar.
**Ne eklenecek:** `cargo +nightly miri test` — özellikle `src/crypto/`
ve `budzero/` gibi unsafe kod barındıran modüllerde.
**Nasıl:** Yeni job, nightly toolchain kurulumu +
`cargo miri test -p <crypto-crate>`.
**Kabul kriteri:** Miri job'ı CI'da var, ilgili crate'lerde UB
bulunmuyor (veya bulunanlar `#[cfg_attr(miri, ignore)]` ile gerekçeli
işaretli, sessizce atlanmıyor).

### 5. cargo-semver-checks
**Neden:** `budlum-wallet-core` mobil (uniffi) ve browser'a
(wasm-bindgen) export ediliyor. Bu paylaşılan crate'te fark
edilmeyen bir breaking API değişikliği, iki platformu birbirinden
sessizce koparabilir.
**Ne eklenecek:** `cargo semver-checks check-release -p
budlum-wallet-core` — her PR'da önceki yayınlanmış sürümle
karşılaştırma.
**Nasıl:** Yeni job, `cargo install cargo-semver-checks` +ilgili
komut.
**Kabul kriteri:** Breaking change tespit edilirse CI kırmızı olur,
bilinçli bir major version bump olmadan geçmez.

### 6. cargo doc -D warnings
**Neden:** Public API'de eksik dokümantasyon veya kırık intra-doc
link'ler, hem geliştirici hem gelecekteki audit için görünmez risk
oluşturur.
**Ne eklenecek:** `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
--all-features`.
**Nasıl:** Mevcut `Repo Lint` job'ına ek adım olarak eklenebilir.
**Kabul kriteri:** Doc build uyarısız geçiyor, zorunlu check.

### 7. MSRV (Minimum Supported Rust Version) pin kontrolü
**Neden:** README "Rust 1.94+" diyor ama CI'ın hangi sürümle test
ettiği sabitlenmiş mi belirsiz — sabitlenmemişse toolchain
güncellemesi sessizce davranış değiştirebilir.
**Ne eklenecek:** `rust-toolchain.toml` dosyasında sürüm sabitlensin,
CI da bu dosyayı okuyarak aynı sürümü kullansın; ayrıca MSRV'nin
gerçekten derlendiğini doğrulayan ayrı bir job (pinned eski sürüm +
en güncel stable, ikisi de geçmeli).
**Kabul kriteri:** `rust-toolchain.toml` var, CI ondan okuyor, MSRV
job'ı ayrıca yeşil.

---

## Protokole özgü invariant testleri

### 8. Tokenomics property test
**Neden:** $BUD arzının 100M sabit tavanı ve iki burn mekanizması
(timed reserve + usage-based metabolic) — elle yazılan birim
testleri her senaryoyu kapsamaz. Property-based test, binlerce
rastgele senaryoda invariant'ı sınar.
**Ne eklenecek:** `proptest` veya `quickcheck` ile: hiçbir işlem
dizisi sonunda toplam arz 100M'ı geçmiyor, hiçbir burn işlemi
negatif bakiye yaratmıyor, burn + mint toplamı her zaman tutarlı.
**Nasıl:** `Cargo.toml`'a `proptest` dev-dependency, yeni test
dosyası `src/tests/tokenomics_proptest.rs`.
**Kabul kriteri:** En az 3 invariant (arz tavanı, negatif bakiye yok,
burn/mint tutarlılığı) property test olarak yazılı ve CI'da koşuyor.

### 9. PoA/permissionless izolasyon testi — ayrı, isimli job
**Neden:** Bu mimarinin en kritik güvenlik sınırı. Şu an genel test
suite'in içine gömülü olabilir; kendi başına görünür, isimli bir CI
job'ı hak ediyor — kırılırsa kimse "genel testlerden biri" diye
gözden kaçırmasın.
**Ne eklenecek:** PoA domain verisinin (validator listesi, KYC
metadata, iç RPC) permissionless tarafa hiçbir yoldan (RPC, event,
cross-domain mesaj) sızmadığını doğrulayan ayrı bir entegrasyon test
seti.
**Nasıl:** `src/tests/poa_isolation.rs` (yoksa oluştur), CI'da
`PoA Isolation` adında ayrı, zorunlu bir job.
**Kabul kriteri:** Job Actions listesinde kendi ismiyle görünüyor,
en az 5 farklı sızma senaryosu (RPC leak, event leak, cross-domain
mesaj leak, log leak, error message leak) test ediliyor.

### 10. Performans regresyon takibi
**Neden:** Blok işleme/tx throughput zamanla, fark edilmeden
yavaşlayabilir — mainnet'te bu kapasite planlamasını doğrudan
etkiler.
**Ne eklenecek:** `criterion` ile mevcut `benches/` altına baseline
kıyaslama, her PR'da bir önceki main'e göre %X'ten görevla yavaşlama
varsa uyarı/fail.
**Nasıl:** `criterion` zaten Rust ekosisteminde standart; CI'da
`cargo bench` sonrası sonuçları bir baseline dosyasıyla kıyaslayan
script (örn. `critcmp`).
**Kabul kriteri:** Bench sonuçları CI artifact'i olarak saklanıyor,
belirlenen eşiği aşan regresyon CI'ı kırmızı yapıyor.

---

## Öncelik sırası (öneri)

1. PoA izolasyon testi (madde 9) — en kritik güvenlik sınırı
2. Genesis + cross-platform determinizm (madde 1-2) — mainnet fork riski
3. Tokenomics property test (madde 8) — ekonomik invariant
4. Migration testi (madde 3) — canlı veri riski
5. Miri (madde 4) — unsafe kod denetimi
6. Geri kalanlar (semver-checks, doc, MSRV, performans) — hijyen,
   zaman buldukça eklenir.
