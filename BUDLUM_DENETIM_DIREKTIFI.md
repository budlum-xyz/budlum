# BUDLUM DİREKTİFİ

Hedef repo: github.com/budlum-xyz/budlum

Kapsam: `THE_BUDLUM_DIREKTIF.md` dosyasının tümü ve açık PR'lar

Genel amaç: Budlum'ı testnete sokmak. Budlum'ı kullanıcı olarak denetlemek ve çalıştırmak. Budlum'ı baştan aşağıya kullanıma hazır hale getirmek. Direktifte testnette olmayacak denen şeyler dahil, hepsini testnete sokmak.

## 1. Amaç

Budlum'ın tamamı sana aittir. Tüm tasarımı sen yaparsın. Tüm kodu sen yazarsın. En eksik parçaya kadar her şeyi sen inşa edersin.

Açık PR'lar merge için hazır hale gelir. Strix AI bu PR'lara bulgular yazmıştır. Her bulgu çözülür. Her çözüm doğrulanır. Çözülen yorumlar silinir. Strix son olarak onay verir. Tüm merge kapıları geçer.

Bu direktif iki iş içerir:

1. Strix bulgularının tamamının çözülmesi.
2. `THE_BUDLUM_DIREKTIF.md` dosyasına bakarak kapsamlı bir denetim yapılması ve bulunan eksiklerin kodlanması. Budlum testnete hazır olur. Bir testnet kullanıcısı gibi Budlum'ın tüm bileşenlerini kullan. Budlum'ı birçok işletim sisteminde çalıştır. Ubuntu bunlardan biridir. Her çalıştırmada çıkan hataları bul. Eksikleri bulduğun anda kodla.

## 2. Temel Kurallar

1. Proje durumu her zaman GitHub üzerinde canlı doğrulanır. Hafızaya veya eski çıktıya güvenilmez.
2. CI (fmt + clippy -D warnings + test) tek yetkili doğrulayıcıdır.
3. Yeni `#[allow(...)]` eklenmez.
4. Yeni `#[ignore]` eklenmez.
5. Eski commit sabitleme (pinning) yapılmaz.
6. Mantık zayıflatılmaz. CI'yı geçirmek için bu yöntemlerden biri kullanılırsa bu bir ihlaldir. Bu bir çözüm sayılmaz.
7. Tamamlanma kanıtı: commit SHA + CI run numarası. Kendi beyanı kanıt sayılmaz.
8. Lisans PolyForm Shield License 1.0.0 olarak kalır.
9. Hiçbir bulgu yorum yazılarak kapatılmaz. Her bulgu kodla veya kanıtlı bir gerekçeyle kapatılır.

## 3. Çalışma Kuralları

1. Kullanıcıya soru sorma. Kendin karar ver.
2. Belirsiz durumda varsayım yapma. Kanıtla. Kanıt yetmezse en olası anlamı seç ve çalışmaya devam et.
3. Durma. Onay bekleme. Kullanıcı seni durdurana kadar çalış.
4. Budlum hazır görünse bile durma. Çalıştırmaya, test etmeye ve düzeltmeye devam et.
5. Bir araç başarısız olursa başka bir yol bul. Çalışmaya devam et.
6. Bir adım başarısız olursa nedenini yaz. Sonra düzelt.
7. Bağlamı kaybedersen `audit-notes` klasöründeki notları oku ve devam et.
8. Strix incelemesini beklerken Aşama 8, 9 ve 10'a devam et.
9. İlerlemeyi kısa ve net raporla.
10. İzin dışı hiçbir işlem yapma. Force-push, geçmiş yeniden yazma ve branch protection atlatma yasaktır.

## 4. Notlar ve PR'lar

1. Strix bulguları, ilgili açık PR'ın dalında çözülür.
2. Diğer tüm iş yeni bir PR'da yapılır. Bu iş notları, denetim bulgularını, düzeltmeleri ve yeni kodu kapsar.
3. Tüm notlar yeni PR'daki `audit-notes` klasörüne yazılır:
   - `plan.md`: plan
   - `strix-ledger.md`: Strix kayıt defteri
   - `findings/`: bulgular. Her alan ve her işletim sistemi için bir dosya
   - `testnet/index.md`: direktif maddelerinin listesi
   - `testnet/<madde adı>.md`: her madde için tasarım
   - `report.md`: rapor
4. Yeni PR'ın açıklaması notların dizinidir. Dosya ekledikçe dizini güncelle.
5. Yeni PR merge edilirse, devam eden iş için `main` dalından yeni bir dal ve yeni bir PR aç.

## 5. Bulgu Formatı

Kendi bulduğun her hatayı şu parçalarla yaz:

- Kimlik: B-0001 biçimi. Birer birer artır.
- Konum: Dosya yolu ve satır numaraları. Hatalı satırları alıntıla. Çalıştırma hatasında işletim sistemini, komutu ve çıktıyı da ver.
- Önem derecesi: kritik, yüksek, orta, düşük veya bilgi.
- Ne yanlış: Hatayı anlat.
- Neden yanlış: Nedeni yaz.
- Neye yol açar: Her etkiyi anlat.
- Nasıl düzeltilir: Düzeltmeyi kelimelerle, adım adım anlat.
- Durum: açık, çözüldü, geçerli değil veya ertelendi. Çözüldü için commit SHA ve CI run numarasını yaz.

Her bulguyu en ince ayrıntısına kadar yaz. Hiçbir ayrıntıyı atlama. Bir mühendis hatayı yalnızca bu nottan düzeltebilmelidir.

Her bulguyu yazmadan önce canlı kodla doğrula.

## 6. Aşama 0: Plan

1. Reponun dosya ağacının tamamını oku.
2. GitHub'da açık PR'ları canlı listele.
3. Bir plan yaz. Planı kontrol listesi olarak yaz. Plan şunları listeler: bakman gereken her dizin, modül ve dosya; açık PR'lar; test edeceğin işletim sistemleri.
4. İşletim sistemi olarak çok sayıda sistem listele. Ubuntu bunlardan biridir.
5. `main` dalından yeni bir dal aç. Dalda `audit-notes` klasörünü aç. Planı `audit-notes/plan.md` dosyasına kaydet.
6. Commit ve push et. `main` hedefli yeni bir PR aç.

## 7. Aşama 1: Durum Tespiti

1. Aşama 0'da listelenen açık PR'ları doğrula. Yeni PR bu listeye girmez.
2. Her PR için kaydet: numara, başlık, kaynak dal, hedef dal, son commit SHA, CI durumu.
3. Her PR için merge engellerini listele: başarısız kontroller, çözülmemiş yorumlar, çakışmalar, eksik onaylar, branch protection kuralları.
4. Her PR'ın diff'ini baştan sona oku.
5. Stack'te yer almayan diğer PR'ları uygun şekilde stack'e ekle ve o PR'ları kapat. Bu botun PR'larının söylediklerine uygun bir kodlama ve birleştirme çalışması yap.

## 8. Aşama 2: Strix Bulgularının Toplanması

1. Her PR'daki Strix yorumlarının tamamını topla. Şunları kapsa:
   - Satır içi (inline) review yorumları
   - Review özetleri
   - PR genel yorumları
   - Strix'in açtığı check sonuçları ve annotation'lar
2. Her bulgu için bir kayıt oluştur:
   - Bulgu kimliği (PR numarası + yorum ID'si)
   - Dosya ve satır
   - Önem derecesi (kritik, yüksek, orta, düşük, bilgi)
   - Bulgunun kısa özeti
   - Durum (açık, çözüldü, geçerli değil, ertelendi)
3. Aynı kök nedene sahip bulguları grupla.
4. Bu kayıt defteri (ledger), yorumlar silinmeden önce tamamlanır. Silme işlemi bu kaydı yok etmez. Kayıt defteri `audit-notes/strix-ledger.md` dosyasında tutulur ve raporda yer alır.

## 9. Aşama 3: Bulguların Çözülmesi

Her bulgu için bu sırayı izle:

1. Bulguyu oku. Kod yolunu uçtan uca izle.
2. Bulgunun geçerli olup olmadığına karar ver. Kanıt topla.
3. Bulgu geçerliyse kök nedeni düzelt. Belirtiyi değil, nedeni düzelt.
4. Bulgu geçersizse teknik gerekçeyi yaz. Gerekçe kodla veya testle desteklenir.
5. Her düzeltme için test yaz veya mevcut testi güçlendir. Test, düzeltilen hatayı yakalar.
6. Düzeltmeyi küçük ve odaklı commit'lere böl. Her commit mesajı bulgu kimliğine atıf yapar.
7. Yerelde şunları çalıştır:
   - `cargo fmt --all -- --check`
   - `cargo clippy --all-targets --all-features -- -D warnings`
   - `cargo test --all-features`
   - CI'nın çalıştırdığı diğer denetimler
8. Commit'leri ilgili dala push et.
9. CI'nın yeşil olmasını bekle. Run numarasını kaydet.

Güvenlik bulguları için ek kural: Düzeltme, aynı sınıftaki diğer kod yollarını da tarar. Aynı hata başka yerde varsa orada da düzeltilir.

Bu sıra, kendi bulduğun hatalar için de geçerlidir.

## 10. Aşama 4: Çözüm Bildirimi ve Yorumların Silinmesi

Bu aşama, yalnızca ilgili düzeltme push edilmiş ve CI yeşil olmuşsa başlar.

1. Her çözülen Strix bulgusuna yanıt yaz. Yanıt şunları içerir:
   - Açık ifade: "Çözüldü."
   - Düzeltmeyi yapan commit SHA
   - CI run numarası
   - Bir veya iki cümlelik teknik özet
2. Geçersiz bulgulara gerekçeli yanıt yaz. Gerekçe kanıt içerir.
3. Yanıttan sonra, çözülen yorumu resolve et.
4. Resolve edilen yorumları sil. Silmeden önce kayıt defterinin güncel olduğunu doğrula.
5. Silme sonrası PR'da çözülmemiş Strix yorumu kalmadığını doğrula.
6. Yorum silme izni yoksa bu adımı atla. Eksik izni raporla. İzni atlatmaya çalışma. Diğer işlere devam et.

## 11. Aşama 5: Strix Onayı

1. Çözülen tüm bulgular için Strix'ten yeniden inceleme iste.
2. Strix'in yeni incelemesini bekle.
3. Strix yeni bulgu yazarsa Aşama 2'ye dön. Yeni bulguları aynı sürece sok.
4. Strix onay verene kadar bu döngüyü sürdür.
5. Onayı doğrula: Strix'in review durumu "onaylandı" olur ve açık bulgu kalmaz.
6. Onayı alınmadan PR merge hazır sayılmaz.

## 12. Aşama 6: Merge Kapıları

Her PR için şu kapıların tamamı geçer:

- [ ] CI yeşil: fmt, clippy `-D warnings`, test
- [ ] Güvenlik kontrolleri yeşil: CodeQL, Zizmor, Gitleaks, cargo-audit, cargo-deny, Semgrep, dependency review
- [ ] Strix onayı alındı
- [ ] Çözülmemiş yorum yok
- [ ] Branch protection kuralları sağlanıyor
- [ ] Gerekli insan onayları alındı
- [ ] Çakışma yok. Dal hedef dalla güncel
- [ ] Yeni `#[allow]`, `#[ignore]`, eski commit sabitleme veya mantık zayıflatma yok
- [ ] Lisans ve bağımlılık politikası korunuyor

Bir kapı geçmezse nedenini bul. Kök nedeni düzelt. Kapıyı geçmek için kuralları gevşetme.

## 13. Aşama 7: Merge

1. Tüm kapılar geçtikten sonra PR'ın merge edilebilir olduğunu GitHub'da canlı doğrula.
2. Merge yöntemi, reponun kurallarına uyar.
3. Merge yapma yetkisi veya izni yoksa PR'ı "merge'e hazır" durumda bırak. Raporla.

## 14. Aşama 8: Kapsamlı Denetim

Bu aşama Strix bulgularından bağımsızdır. Amaç, Strix'in yakalamadığı eksikleri bulmaktır.

### Direktifin okunması

1. `THE_BUDLUM_DIREKTIF.md` dosyasını repoda ara. Önemli olan dosya budur.
2. Dosyayı baştan sona oku. Her satırı oku.
3. Dosyadaki her maddeyi listele. Testnet için gerekli olan maddeleri listele. Testnette olmayacak denen maddeleri de listele. Hepsini testnete sokacaksın.
4. Listeyi `audit-notes/testnet/index.md` dosyasına kaydet.

### Denetim sırası

1. Plandaki her dosyayı incele. Dosya ağacının başından sonuna git.
2. Her dosyanın her satırını oku. Hiçbir dosyayı atlama. Hiçbir satırı atlama.
3. CI workflow'larının çalıştırdığı kontrolleri çalıştır. Reponun güvenlik araçlarını da çalıştır.
4. Bulduğun her hatayı bulgu olarak yaz (Bölüm 5). Bir kontrolün veya aracın her başarısızlığını da yaz.
5. Her hatayı hemen düzelt. Aşama 3'teki sırayı izle. Kodu yeni PR'da yaz.
6. Bulguları `audit-notes/findings` klasörüne kaydet. Her alan için bir dosya kullan.
7. Bitirdiğin her dosyayı planda işaretle.
8. Her alandan sonra commit ve push et.

Sonraki her turda kaçırdığın hataları ara. Aynı bulguyu iki kez yazma.

### Denetim alanları

1. **Konsensüs alanları:** PoW, PoS, BFT ve izole PoA katmanı. Alanlar arası sızıntı var mı kontrol et.
2. **Settlement primitifleri:** DomainFinalityAdapter, GlobalBlockHeader, ReplayNonceStore, CrossDomainMessage (BDLM_DOMAIN_COMMITMENT_V1 hash etiketi), BridgeState, DomainStatus (Active/Frozen/Retired). Replay, durum geçişi ve hash etiketi tutarlılığını doğrula.
3. **BudZero / BudZKVM:** Trace matrisi, AIR kısıtları, opcode davranışı. VerifyMerkle 64-depth üretimde kapalı kalır. Bu PR'larda açılmaz.
4. **Cüzdan çekirdeği (budlum-wallet-core):** Anahtar yönetimi, imzalama, RPC istemcisi. BIP39 + SLIP-0010 ed25519 türetimi. Adres = Ed25519 genel anahtarının SHA3-256 özeti. PoA akışı, izinsiz (permissionless) akıştan izole kalır.
5. **Depolama (B.U.D.):** İçerik adresleme, Reed-Solomon silme kodlaması, shard yerleşimi, şifreleme. Bağlantı (wiring) durumunu doğrula.
6. **Ekosistem modülleri:** src/ai, src/lubot, src/pollen, src/socialfi, src/bns, src/budlumxyz.
7. **CI ve tedarik zinciri:** Workflow izinleri, secret kullanımı, aksiyon sürümleri, BADGE_PUSH_TOKEN riski.

### Denetim kontrol listesi

Her alan için şunları kontrol et:

- `unwrap()`, `expect()`, `panic!` ve sınır dışı indeks riskleri
- Tamsayı taşması ve aritmetik hatalar
- `unsafe` kullanımı ve gerekçesi
- Girdi doğrulama eksikleri
- Zamanlama yan kanalları ve sabit zamanlı karşılaştırma ihtiyacı
- Rastgelelik kaynağı ve anahtar materyalinin bellekten silinmesi (zeroize)
- Hata yönetimi ve hata yayılımı
- Eşzamanlılık: kilitler, yarış koşulları, kilitlenme (deadlock)
- Replay ve nonce yönetimi
- Serileştirme ve hash alanı ayrımı (domain separation)
- Eksik testler, özellikle sınır durumları ve olumsuz yollar
- Ölü kod, kullanılmayan bağımlılıklar, sürüklenmiş (drift) dokümantasyon
- Dokümantasyon ve kodun uyumu

### Eksiklerin kodlanması

1. Önemli olan dosya THE BUDLUM DİREKTİF dosyasıdır. Her eksiği bulgu kaydı olarak kaydet. Önem derecesini ata.
2. Tüm eksikleri kodla: kritik, yüksek, orta ve düşük. Kodu yeni PR'da yaz.
3. Her yeni kod parçası için test yaz.
4. Aşama 3'teki yerel doğrulama komutlarını çalıştır.

## 15. Aşama 9: Birçok İşletim Sisteminde Çalıştırma

1. Plandaki her işletim sistemini al. Ubuntu bunlardan biridir.
2. Her sistemi konteyner, sanal makine veya CI runner ile edin.
3. Her sistemde Budlum'ı derle. Budlum'ı çalıştır. Testleri çalıştır.
4. Her işletim sisteminde Budlum'ın tüm bileşenlerini bir testnet kullanıcısı gibi kullan.
5. Her çalıştırmada çıkan her hatayı bulgu olarak yaz (Bölüm 5).
6. Her hatayı hemen düzelt. Aşama 3'teki sırayı izle. Düzeltmeden sonra Budlum'ı hatanın çıktığı işletim sisteminde yeniden çalıştır.
7. Bulguları `audit-notes/findings` klasörüne kaydet. Her işletim sistemi için bir dosya kullan.
8. Her sistemden sonra commit ve push et.

## 16. Aşama 10: Testnet Maddelerinin İnşası

1. `audit-notes/testnet/index.md` dosyasındaki her maddeyi al.
2. Maddenin tam tasarımını yaz. Tasarımı `audit-notes/testnet/<madde adı>.md` dosyasına kaydet.
3. Maddenin kodunu yaz. Maddenin testlerini yaz.
4. CI kontrollerini çalıştır. Her başarısızlığı nedeninde düzelt.
5. Her maddeden sonra commit ve push et.

Her tasarım şu parçaları içerir:

- Gereksinim, `THE_BUDLUM_DIREKTIF.md` dosyasının ifade ettiği biçimde.
- Kodun şimdi ne yaptığı.
- Neyin eksik veya yanlış olduğu. İlgili her bulguya kimliğiyle bağlantı ver.
- Maddeyi inşa etme adımları, sırayla.
- Değişecek dosyalar, modüller ve fonksiyonlar.
- Maddenin çalıştığının nasıl doğrulanacağı.

Her tasarımı en ince ayrıntısına kadar yaz. Yeni bir bulgu tasarımı değiştirirse tasarımı güncelle.

## 17. Aşama 11: Tekrar

1. Aşama 10 bitince planın tüm işaretlerini kaldır.
2. Aşama 8'e dön.
3. Sonsuza kadar tekrarla. Budlum hazır görünse bile durma.

## 18. Rapor

Raporu `audit-notes/report.md` dosyasında tut. Her turdan sonra güncelle. Rapor şunları içerir:

1. **Durum tablosu:** Her PR için son SHA, CI run numarası, Strix durumu, merge kapıları.
2. **Bulgu kayıt defteri:** Tüm Strix bulguları, durumları ve çözen commit SHA'ları.
3. **Denetim bulguları:** Kendi denetiminde bulunan eksikler ve kodlananlar.
4. **Henüz kodlanmamış eksikler:** Kodlanmayan eksikler ve önerilen sonraki adımlar.
5. **İhlal beyanı:** Hiçbir yasak yöntem kullanılmadığının doğrulaması. Kullanıldıysa açıkça belirt.
6. **Açık riskler:** BADGE_PUSH_TOKEN riski ve üçüncü taraf güvenlik denetiminin yokluğu gibi bilinen riskler.

Her iddia kanıt içerir: commit SHA ve CI run numarası.

## 19. Yazım Stili

Tüm notları kısa ve düz cümlelerle yaz. Şimdiki zamanı kullan. Uzun çizgi (em dash) kullanma.

## 20. Token

Bu direktifin sonunda bir GitHub token verilir. Şu kurallar geçerlidir:

1. Token yalnızca bu sohbet için geçicidir. Sohbet bittiğinde token geçersiz sayılır.
2. Token yalnızca bu direktifteki işler için kullanılır.
3. Token, ortam değişkeni olarak geçici kullanılır. Token yalnızca çalışma alanında kalabilir.
4. Kullanıcı işin bittiğini söylediğinde token oturumdan kaldırılır. Token, senin hazırladığın dosya ve dokümanlardan da silinir. Bunu kullanıcıya sormazsın.
5. Token hiçbir commit, PR yorumu, log veya rapora girmez. Token hiçbir mesajda yazdırılmaz.
6. Tüm işlemler kullanıcının GitHub kimliğiyle yapılır.
7. Bu direktif dosyasını commit etme.
8. Son satırda `BURAYA_TOKEN_YAPISTIR` yazıyorsa token verilmemiştir. Token olmadan çalışmaya devam et. Token isteme.

TOKEN: BURAYA_TOKEN_YAPISTIR
