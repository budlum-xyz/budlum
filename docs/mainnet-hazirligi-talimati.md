# MAINNET HAZIRLIĞI — Talimat

Bu doküman CI'ın yeşile dönmesinden **sonraki** görevyı kapsar: Budlum'u
devnet/testnet adayından gerçek mainnet adayına taşımak için kapatılması
gereken açıklar. Kaynak: repo'nun kendi roadmap tablosu (README) + önceki
strateji analizleri. Her madde için ne eksik, neden önemli, kabul kriteri
ne olmalı yazıyor.

---

## Önce oku

- Bu liste **repo'nun kendi beyanına** dayanıyor (README'deki durum
  tablosu, "✅ Closed" / "❌ Araştırma" işaretleri). Kendi beyanı = kanıt
  değil. Her madde için "kapalı" denen yerlerde bile önce ilgili
  dosya/test/checklist'i göster, sonra kapalı say.
- Sıralama önem sırasına göre değil, kategoriye göre. **Kritik** bölüm
  bitmeden Yüksek/Orta'ya geçilmez.

---

## KRİTİK — Bunlar olmadan mainnet konuşulmaz

### 1. Bağımsız harici audit
**Durum:** `docs/AUDIT_CHECKLIST.md` hazır ama bağımsız bir 3. parti
audit **yapılmadı**. Repo bunu kendi de itiraf ediyor ("audited" iddiası
yok).
**Yapılacak:** Audit checklist'i tamamla, bir audit firmasıyla kapsam
belirlenecek şekilde paketle (consensus, bridge, ZK verifier, RPC auth).
Bu bir kod görevi değil ama kod tarafında audit'i kolaylaştıracak şeyler
(net modül sınırları, dokümante edilmiş invariant'lar) hazırlanabilir.
**Kabul kriteri:** Audit kapsamı dokümanı + bağımsız firma teklifi/anlaşması var.

### 2. Z-B (BudZKVM VerifyMerkle) 64-depth soundness
**Durum:** Kısmi düzeltmeler yapıldı ama **Production ISA'da hâlâ gate'li**
— yani gerçek kullanılmıyor, kapalı tutuluyor. B.U.D. storage'ın Görev 3'ü
(gerçek Proof-of-Storage) buna bağlı ve şu an "proof-of-storage" iddiası
resmen yapılmıyor (sahte-yeşil yol riski, vision §9.1'de yazıyor).
**Yapılacak:** 64-depth'te pozitif/negatif test setiyle tam soundness
kanıtı. Gate ancak bu kanıt yeşil olunca kaldırılır.
**Kabul kriteri:** VerifyMerkle Production ISA'da açık, 64-depth testleri
CI'da ayrı bir zorunlu job olarak koşuyor ve geçiyor.

### 3. BLS/PQ HSM — vendor-native mekanizma
**Durum:** Disk key'ler yasak (iyi), ama gerçek donanım HSM entegrasyonu
sadece dev/test mock backend seviyesinde. Ed25519 için PKCS#11 var,
BLS/PQ için yok.
**Yapılacak:** En az bir gerçek HSM vendor'ıyla (örn. YubiHSM, Thales,
AWS CloudHSM) BLS/PQ imzalama entegrasyonu ve devnet'te canlı test.
**Kabul kriteri:** Mainnet validator config'i disk-key olmadan gerçek
HSM ile ayakta kalıyor, runbook güncel.

### 4. Relayer güven modeli kararı
**Durum:** Hafızada not düşülmüştü — single/permissionless/threshold
seçeneklerinden hangisi seçilecek, henüz karara bağlanmamış görünüyor.
bud-node RPC'nin bridge tarafı bu karara göre şekillenir.
**Yapılacak:** Ayaz ile bu kararı netleştir (bu bir kod görevi değil,
Arena'ya devredilmeyecek — sadece flag et, uygulama sonra gelir).
**Kabul kriteri:** Karar dokümante edildi, ilgili RPC endpoint'leri buna
göre tasarlandı.

---

## YÜKSEK — Kritik kapanmadan başlanmaz ama hemen arkasından gelir

### 5. Fuzzing süresi
**Durum:** CI'daki "Fuzz Quick" job'ı 90 saniye × 5 target — bu bir
duman testi, gerçek fuzzing değil. Devnet checklist'inde hedef
24-48 saat sürekli fuzzingdi.
**Yapılacak:** "Fuzz Nightly" workflow'u zaten var (Actions listesinde
görüldü) — bunun gerçekten 24-48 saat sürdüğünü ve düzenli koştuğunu
doğrula, sonuçları raporla.
**Kabul kriteri:** Son 2 haftalık Fuzz Nightly run geçmişi + bulunan/
kapatılan crash sayısı raporu.

### 6. Bug bounty programı
**Durum:** Plan var (4 seviye: Critical/High/Medium/Low, 90 gün embargo,
Discord/Telegram triage) ama hayata geçtiğine dair kanıt yok.
**Yapılacak:** `SECURITY.md`'yi bu plana göre güncelle, gerçek bir triage
kanalı aç, ödül tablosunu yayınla.
**Kabul kriteri:** SECURITY.md yayında, en az bir dış kişi programı
görüp rapor gönderebiliyor.

### 7. PoW light-client + eski proof yolu
**Durum:** Yeni bounded header-chain proof'u var ama "legacy declared-depth
proofs" hâlâ mint-gated olarak kod tabanında duruyor.
**Yapılacak:** Legacy yolun tamamen kaldırılıp kaldırılamayacağına karar
ver; kalacaksa neden mainnet'e kadar tutulduğu dokümante edilsin.
**Kabul kriteri:** Legacy proof yolu ya silindi ya da gerekçesiyle
belgelendi, her iki durumda da mint-gate testleri CI'da var.

### 8. Bağımlılık (dependabot) birikintisi
**Durum:** 7 açık dependabot PR'ı var, bazıları majör version atlıyor
(p3-fri 0.5.2→0.6.1, bincode 1.3.3→3.0.0). Mainnet öncesi bağımlılık
sürüklenmesi risk.
**Yapılacak:** Her PR'ı tek tek değerlendir — breaking change var mı,
CI'da ayrı test et, merge veya reddet.
**Kabul kriteri:** Açık dependabot PR sayısı 0 veya gerekçeli "won't merge"
etiketiyle kapatılmış.

### 9. Coverage job'ı sürekli kırmızı
**Durum:** CI'daki "Coverage (nextest + llvm-cov, ratchet)" job'ı
kontrol edilen **her** run'da exit code 100/101 ile fail ediyor —
Budlum Core düzelse bile bu ayrı bir hata. Devnet checklist'inde
"cargo tarpaulin/grcov coverage raporları" hedefi vardı; bu job o
hedefin karşılığı ve şu an çalışmıyor.
**Yapılacak:** Coverage job'ının neden kırmızı olduğunu (ratchet eşiği
mi aşılıyor, yoksa build mi kırık) ayrı incele — Budlum Core fix'ine
otomatik takılacağını varsayma.
**Kabul kriteri:** Coverage job'ı yeşil, güncel kapsama yüzdesi
raporlanıyor.

### 10. Governance / parametre değişiklik süreci
**Durum:** Mainnet'te fee/reward/registry parametrelerini kim, nasıl
onayla değiştirebilir — dokümanlarda net bir tanım göremedim.
**Yapılacak:** Governance modelini yaz (kim önerir, kim onaylar, ne
kadar sürede yürürlüğe girer, acil durum override'ı var mı).
**Kabul kriteri:** `docs/GOVERNANCE.md` var, parametre değişikliği bu
sürece göre test ediliyor.

### 11. PoA/kurumsal domain gerçek donanımla hiç test edilmedi
**Durum:** `enterprise-poa.toml` PKCS#11 + env secrets istiyor ama
gerçek bir kurumsal/banka pilot ortamında (BDDK/KYC senaryosu) canlı
denendiğine dair kanıt yok — sadece config seviyesinde var.
**Yapılacak:** Gerçek veya gerçeğe yakın bir pilot ortamda PoA
domain'ini uçtan uca çalıştır (validator kaydı, KYC akışı, izolasyon
testi).
**Kabul kriteri:** Pilot çalıştırma raporu + izolasyon ihlali
bulunmadığına dair test kanıtı.

---

## ORTA — Mainnet'i engellemez ama güven/itibar riski taşır

### 12. README/badge tutarlılığı
**Durum:** Repo `budlum-xyz/budlum`'a taşındı ama badge'ler ve clone
komutu hâlâ eski `lubosruler/budlum`'a işaret ediyor.
**Yapılacak:** Tüm URL'leri güncelle.
**Kabul kriteri:** README'de `lubosruler` geçen hiçbir link kalmadı.

### 13. Formal verification / Privacy / AI execution layer
**Durum:** Üçü de resmen "araştırma" görevsında, kod yok. Mainnet
blokeri değil ama yol haritasında büyük iddialar var — beklenti
yönetimi gerekiyor.
**Yapılacak:** Bu üç madde için "mainnet v1'de YOK, v2 planı" diye
açıkça yazılı bir kapsam-dışı beyanı README'ye eklensin (yatırımcı/
kullanıcı karşısında netlik için).
**Kabul kriteri:** README'de net "mainnet v1 kapsamı" bölümü var.

### 14. Çoklu Arena instance koordinasyonu
**Durum:** ARENA1/ARENA2/ARENA3/ARENAX gibi paralel instance'lar aynı
fix'i tekrar üretip merge conflict yaratıyor.
**Yapılacak:** Mainnet'e yakın dönemde tek seferde tek instance/tek
görev kuralı — paralel çalışma sadece birbirinden bağımsız modüllerde.
**Kabul kriteri:** Commit geçmişinde "ayni hunk" / "merge(arena3)" tipi
çakışma commit'leri mainnet öncesi son 2 haftada görülmüyor.

### 15. Scope creep — CI/kritik iş bitmeden yeni kapsam açma
**Durum:** Gözlemlenmiş örnek: CI hâlâ kırmızıyken main'e tamamen
yeni bir özellik spec'i ("zincir fork / tam geçmiş migration") merge
edildi. Bu tek seferlik değil, tekrar eden bir davranış kalıbı —
Arena aktif bir hata açıkken yeni iş planlamaya başlıyor.
**Yapılacak:** "Aktif kritik/yüksek madde varken yeni spec/döküman
commit'i yok" kuralını Arena'nın görev tanımına açıkça yaz (Genel
kurallar #2 ile aynı, burada ayrı madde olarak takip edilsin çünkü
tekrarlanan bir desen).
**Kabul kriteri:** Son 2 haftada, açık bir kritik/yüksek madde varken
atılmış yeni-kapsam commit'i yok.

### 16. Verifier Registry birleştirilmedi — mimari borç
**Durum:** Master Verifiers (DeEd), content validator (SocialFi),
relayer'lar, supply chain attester (Budlum Go) hepsi aynı "kim
güvenilir, nasıl slash edilir" problemini ayrı ayrı, birbirinden
habersiz çözüyor. Daha önce base layer'da tek, stake-tabanlı bir
Verifier Registry önerilmişti; uygulanmış mı belirsiz.
**Yapılacak:** Mevcut RoleId-tabanlı Verifier Registry'nin bu dört
kullanım alanını da kapsayıp kapsamadığını doğrula; kapsamıyorsa
birleştirme planı çıkar (mainnet v1 için şart değil ama v1 sonrası
teknik borç birikmesin diye şimdi kayda geçsin).
**Kabul kriteri:** Karar dokümante edildi — ya birleştirildi ya da
"v1'de ayrı kalacak, v2'de birleşecek" diye net yazıldı.

### 17. Açık PR'larda bağımsız review süreci yok
**Durum:** #13 (fix ci kök-neden) ve #11 (docs/adim5 handoff) günlerdir
açık, merge edilmemiş. lubosruler hem yazıp hem merge ediyor gibi
görünüyor — bağımsız bir gözden geçiren yok.
**Yapılacak:** En azından mainnet'e yakın kritik değişiklikler için
(consensus, bridge, RPC auth) ikinci bir göz zorunlu kılınsın —
Ayaz teknik değil ama en azından CI+diff özeti üzerinden onay versin.
**Kabul kriteri:** Kritik modüllere dokunan PR'larda merge öncesi en
az bir onay/inceleme adımı var.

---

## STRATEJİK — kod görevi değil ama mainnet öncesi netleşmeli

### 18. Monolitik vs modüler anlatı gerilimi
**Durum:** Budlum'un "evrensel settlement layer" konumlandırması ile
Celestia/EigenLayer'ın unbundling (parçalara ayırma) tezi arasında bir
gerilim var. Bu bir kod sorunu değil ama yatırımcı/kullanıcı
konuşmalarında "neden monolitik, neden şimdi" sorusuna net bir cevap
olmadan mainnet lansmanı zayıf kalır.
**Yapılacak:** Bu, Arena'ya değil Ayaz'a düşen bir görev — pozisyonlama
netleşmeden mainnet lansman metni yazılmasın.
**Kabul kriteri:** Yok — bu madde takip listesinde kalsın, kod
tarafını etkilemez ama unutulmasın diye burada duruyor.

---

## Genel kurallar (her madde için geçerli)

1. Her madde kapatıldığında: **commit hash + CI run linki** paylaşılır.
   Rapor metni tek başına kanıt sayılmaz.
2. Kritik veya Yüksek bir madde üzerinde çalışırken yeni kapsam
   (yeni özellik spec'i, yeni doküman) açılmaz — önce elindekini bitir.
3. "Kapalı" / "Closed" / "✅" işaretleri sadece bağımsız doğrulanabilir
   bir kanıtla (test, CI run, harici belge) kullanılır.
4. Coverage/test eşiklerini geçmek için test silme veya `#[ignore]`
   ile gizleme yasak — madde 9 (Coverage) bu yüzden ayrı ve açıkça
   yazıldı.
