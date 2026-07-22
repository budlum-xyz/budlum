# : Zincir Fork / Tam Geçmiş Klonlama (Chain Fork — Full History Migration)

## Bağlam ve Amaç

Testnette bir hack/olay durumunda, saldırıdan önceki temiz bir blok yüksekliğine kadar
**tüm blok geçmişini** yeni bir ağa taşıyabilmemiz gerekiyor (Ethereum → Ethereum Classic
fork'una benzer bir mekanizma). Bu, sadece bakiye/NFT snapshot'ı değil — genesis'ten
fork noktasına kadar olan komple, doğrulanabilir zincir geçmişi anlamına gelir.

Bu doküman bir **spec**'tir, uygulama detayları (dosya adları, fonksiyon imzaları)
Arena/geliştirici tarafından Budlum'un mevcut kod yapısına göre belirlenmelidir.

## Kapsam

### Kapsam İçi
1. `export-chain` komutu: genesis'ten belirtilen blok yüksekliğine (`--to-height`)
   kadar olan **tüm blokları + state'i** taşınabilir bir formatta dışa aktarır.
2. `import-chain` / fork-genesis komutu: bu export'u yeni bir ağın başlangıç
   verisi olarak alır, yeni zincir bu geçmişin devamı gibi başlar.
3. Multi-domain tutarlılığı (aşağıda detaylı) — PoW/PoS/BFT + izole PoA domain'i.
4. Doğrulama: export edilen geçmişin, orijinal zincirin kendi consensus kurallarına
   göre yeniden oynatılabilir (replay edilebilir) olduğunun testi.

### Kapsam Dışı (bu görevde YOK)
- Olayı otomatik tespit eden izleme/alert sistemi (ayrı ).
- Fork noktasının "hangi blok temiz" olduğuna karar veren otomasyon — bu insan kararı
  olarak kalıyor, komut sadece "şu yükseklikte fork et" parametresini alır.
- Mainnet'e özel governance/oylama mekanizması (şimdilik sadece testnet senaryosu).

## Gereksinimler

### 1. Export (`export-chain`)
- Girdi: başlangıç (genesis) ve bitiş (`--to-height`) blok yüksekliği.
- Çıktı: tek bir taşınabilir dosya/dizin — tüm bloklar (header + body + imzalar) +
  o yükseklikteki final state (hesap bakiyeleri, NFT sahiplikleri, contract storage).
- Format insan-denetlenebilir olmalı ki export sonrası "gerçekten temiz mi" diye
  manuel kontrol edilebilsin (ör. JSON/CBOR + bir özet/manifest dosyası: toplam
  hesap sayısı, toplam NFT sayısı, son blok hash'i).

### 2. Import / Fork Genesis (`import-chain`)
- Export edilen veriyi okuyup yeni ağın genesis'i olarak kurar.
- Yeni ağ, import edilen son bloğu "genesis" gibi değil, gerçek geçmişin devamı
  olarak görmeli (blok yükseklik sayacı sıfırlanmamalı, sürekli artmalı).
- Yeni ağın validator/verifier seti bu noktada **yeniden tanımlanabilir** olmalı
  (eski validator seti otomatik taşınmayabilir — bu bir CLI parametresi olsun).

### 3. Multi-Domain Tutarlılığı (kritik — Budlum'a özgü)
Budlum'da tek bir zincir yok; PoW/PoS/BFT permissionless domain'ler + izole PoA
domain'i var. Bu yüzden export/import şunları garanti etmeli:
- **Her ConsensusDomain'in state'i kendi içinde tutarlı** export edilmeli
  (bir domain fork noktasında, diğeri bir blok öncesinde donmuş olmamalı).
- **Yarım kalmış CrossDomainMessage yok**: fork noktasında domain'ler arası
  gönderilmiş ama henüz teyit edilmemiş (in-flight) mesaj varsa, bunun export'ta
  ya tamamlanmış ya da güvenle iptal edilmiş şekilde ele alınması gerekiyor.
  Yarım kalmış mesajlarla fork edilirse, yeni zincirde kilitlenmiş/kaybolmuş
  varlıklar oluşabilir.
- **PoA/kurumsal domain izolasyonu korunmalı**: fork sonrası da PoA domain'i
  permissionless kullanıcı akışından ayrı kalmalı; export/import bu izolasyonu
  ihlal etmemeli (ör. PoA'nın iç verisini permissionless tarafa sızdırmamalı).

### 4. Doğrulama / Test Gereksinimleri
- Export edilen geçmiş, sıfırdan bir node'da **replay edilip aynı state hash'ine
  ulaştığını** doğrulayan bir test olmalı (deterministik yeniden oynatma testi).
- NFT sahiplikleri için: export öncesi ve import sonrası state'te belirli bir
  test setinin (ör. rastgele seçilmiş 20 NFT) sahiplik eşleşmesini doğrulayan
  entegrasyon testi.
- Cross-domain mesaj kenar durumu (in-flight mesajla fork) için en az bir test:
  mesaj ne kaybolmalı ne de çift işlenmeli.

## Kabul Kriterleri
- [ ] `export-chain` ve `import-chain` komutları çalışıyor, CLI `--help` çıktısı var.
- [ ] Üç domain tipinden (PoW, PoS, BFT) en az birer örnek + PoA domain'i ile
      uçtan uca test: export → yeni node'da import → state hash eşleşmesi.
- [ ] In-flight CrossDomainMessage senaryosu için test var ve geçiyor.
- [ ] `cargo fmt`, `cargo clippy -D warnings`, `cargo test --lib` hepsi yeşil.
- [ ] Yeni `#[allow(...)]` eklenmemiş, mevcut testler `#[ignore]` ile
      gizlenmemiş (bkz. standart kural: CI gevşetilmez).
- [ ] Son commit hash'i ve CI run linki ayrıca paylaşılacak — rapor metni tek
      başına yeterli kanıt sayılmaz.

## Notlar
- Fork noktasının seçimi (hangi blok "temiz") bu görevin parçası değil; komut
  sadece parametre olarak yükseklik alır.
- Export formatı ne kadar büyükse (tam geçmiş) o kadar depolama/süre gerektirir —
  büyük veri setlerinde export/import süresini ölçüp raporla (yaklaşık kaç
  blok/saniye işleniyor gibi).
