# Budlum — Alınmış Tüm Kararlar için 120 Soruluk Anket (ARENA2 + ARENA3 genişletmesi, 2026-07-17)

> **Amaç:** Budlum'un Phase 0.06'dan Phase 9'a kadar alınmış tüm stratejik ve teknik kararlarını tek bir ankette toplamak. Her soru teknik detay + parantez içinde teknik olmayan açıklama içerir. Seçenek sayısı 3-5, tüm olası cevapları kapsayacak şekilde. Cevap anahtarı kullanıcı tarafından verilecek. **Revizyon (ARENA3):** Sorular değiştirilmeden tüm non-teknik açıklamalar uzun/jargonsuz/sonuç-odaklı hale getirildi (hiçbir teknik kelime yok); Q101-Q120 eklendi.

> **Kaynaklar:** `docs/PHASE0.06_PLAN.md`, `PHASE0.08_PLAN.md`, `PHASE0.10_PLAN.md`, `PHASE0.378_*`, `PHASE0.42_PLAN.md`, `PHASE1_RAPOR.md`, `MAINNET_READINESS.md`, `BUDLUM_CONSTITUTION.md`, `RD_SOCIALFI_DWEB_VISION.md`, `PERSONAS.md`, `THREAT_MODEL.md`, `ORG_ROADMAP_AUDIT.md`, `PHASE8.9_ANALIZ_A1.md`, `PHASE9_VIZYON_KOD_CELISKI_DENETIM_ARENAX_2026-07-17.md`, `STATUS_ONLINE.md`, `CLAUDE.md`, `ARENA_AI.md`, `AUDIT_CHECKLIST.md`, `BUG_BOUNTY.md`, `MAINNET_GENESIS_CEREMONY.md`, `config/*.toml`, `src/core/chain_config.rs`, `src/crypto/pkcs11.rs`, `budzero/bud-isa/src/lib.rs`.

---

## Q1 — Phase sistemi isimlendirmesi
**Teknik:** TUR/ADIM serisi Phase sistemine taşındı (`ADIM1=Phase1`, `Tur1=Phase0`, `Tur10=Phase0.30`, `Tur25=Phase0.60`). Formül `t<10 → 0.02×(t-1)`, `t≥10 → 0.30+0.02×(t−10)`. (Repo genelinde TUR/ADIM kelimeleri Phase ile değiştirildi, eski dal adları hariç)
**Non-teknik (herkes için):** Bir ekibin her şeye aynı adı vermesi gibi düşünün: biri 'tur' diyor, biri 'adım' diyor, biri 'faz' diyor; yeni gelen biri hangisinin ne olduğunu şaşırır ve yanlış işi yanlış zamanda yapar. Bu karar tek isim kullanmayı seçiyor; doğruysa herkes aynı takvimi okur, raporlar birbiriyle konuşur, yeni katılan ekip üyeleri günler değil saatler içinde hızlanır. Yanlış seçilirse — yani iki isim birden yaşarsa — eski alışkanlık ölmez, bir süre sonra kimse hangi ismin güncel olduğundan emin olamaz; bu da aylar sonra 'o iş bitmişti sanıyordum' türünden pahalı yanlış anlamalara döner. İsim karmaşası küçük görünür ama Budlum gibi uzun bir yolculukta pusulanın sürekli birkaç derece şaşması demektir; günü geldiğinde gerçek ağın açılış hazırlığını sessizce kemirir.
- A) Phase sistemi doğru, TUR/ADIM tamamen kaldırılsın
- B) Eski TUR/ADIM isimleri de paralel kalsın (çift isim)
- C) Sadece TUR kaldırılsın, ADIM kalsın
- D) Hiçbir şey değişmesin, eski isimler kalsın

## Q2 — Budlumdevnet dokunulmazlığı
**Teknik:** `github.com/budlum-xyz/budlumdevnet` main HEAD `6613219a`, son push 2026-07-11 21:11 UTC'den beri dokunulmadı. Budlum repo'sunun temelini aldığı eski kod sabit kalmalı. (Eski kodun değişmediğini CI ile doğruluyoruz)
**Non-teknik (herkes için):** Yeni bina yapılırken eski temele dokunmamak gibi: Budlum'un üzerine kurulduğu eski çalışma, referans noktası olarak dondurulmuş durumda. Bu karar o temelin bir daha asla değiştirilmeyeceğini söylüyor. Böyle kalırsa yarın bir şüphe doğduğunda herkes 'eskiyle yeniyi karşılaştır' diyebilir ve gerçek anında görülür; denetim yapan dış uzmanlar da sağlam bir zemine bakar. Tersine izin verilirse — eski temele ara sıra küçük dokunuşlar yapılırsa — bir gün kimse 'bu davranış eskiden beri mi vardı, yoksa sonra mı eklendi' sorusuna güvenle cevap veremez; Budlum'un geçmişi kaygan bir zemine döner ve en kritik anda, gerçek ağ açılmadan önceki son kontrollerde, güven sarsıcı bir belirsizlik yaşanır.
- A) Budlumdevnet kesinlikle dokunulmamalı, sadece okunmalı
- B) Küçük düzeltmeler budlumdevnet'e de uygulanabilir
- C) Budlumdevnet tamamen budlum'a merge edilsin

## Q3 — Force-push yasağı
**Teknik:** `git push --force`, `--force-with-lease` kesin yasak. Conflict durumunda `git pull --rebase` + normal push. Shallow clone sorunu `git fetch --unshallow`. (STATUS.md §4.2)
**Non-teknik (herkes için):** Ortak bir dosyada çalışırken birinin 'benimki doğru' deyip başkasının yazdıklarını zorla silmesi gibi: hızlı görünür ama arkada kimin ne kaybettiği belli olmaz. Bu karar zorla üstüne yazmayı kesin olarak yasaklıyor; çakışma olursa herkes önce karşı tarafı alıp sonra kendi değişikliğini üstüne koyuyor. Doğru uygulanırsa hiçbir katkı sessizce kaybolmaz; bir hata çıkarsa geriye dönüp kimin neyi ne zaman eklediği rahatça izlenir. Yasak kalkarsa gece yarısı yapılan tek bir sert hamle, haftalarca emek verilmiş bir işi geri döndürülemez şekilde silebilir ve ekipte 'benim işim nereye gitti' güvensizliği doğar; Budlum gibi birden çok zekânın aynı eve tuğla taşıdığı bir projede bu, ana binaya dinamit koymak gibidir.
- A) Force-push kesin yasak kalsın
- B) --force-with-lease serbest olsun
- C) Force-push serbest, hızlı ilerleyelim

## Q4 — Workflow dosyası push yasağı
**Teknik:** Bot token `workflows: write` izni yok, `.github/workflows/ci.yml` değişiklikleri kullanıcı manuel ekler. (STATUS.md §4.3, STATUS_ONLINE F8)
**Non-teknik (herkes için):** Otomatik denetçinin ayarlarını yine otomatik denetçinin değiştirmesini düşünün: fabrikada kalite kontrol cihazının kendi hassasiyetini kendisinin düşürmesi gibi bir şey. Bu karar, kalite kapısının kurallarını ancak insanların değiştirebileceğini söylüyor. Böyle kalırsa bir robot hata yapıp kapıyı gevşetse bile insan onayı olmadan gevşeme gerçekleşmez; Budlum'un kalite standardı bir gece ansızın ve kimse fark etmeden düşmez. İzin verilirse bir gün ufak bir yanlışlıkla 'artık her şey serbest' ayarı devreye girer, hatalı işler kusursuzmuş gibi damgalanıp içeri alınır ve bunun bedeli ancak gerçek ağda, para ve veri risk altındayken ödenir.
- A) Yasak kalsın, kullanıcı eklesin
- B) Botlara workflows izni verilsin
- C) Workflow dosyaları tamamen kaldırılsın

## Q5 — Kanıt standardı (SHA/dosya:satır/CI-job)
**Teknik:** Her iddia `git cat-file -t <sha>`, `grep -n`, `gh api .../check-runs` ile kanıtlanmadan audit'e yazılmaz. Kanıtsız commit referansı yasak. (STATUS.md §4.1)
**Non-teknik (herkes için):** Mahkemede 'bana güvenin' demekle belge sunmak arasındaki fark gibi: bu kural her iddianın yanına elle tutulur kanıt konmasını şart koşuyor. Böyle yaşanırsa hiç kimse havada kalan bir 'bitirdim, oldum, yanlış' demez; herkes gösterdiği kanıt üzerinden konuşur ve yanlışlar dakikalar içinde yakalanır. Bu standart essiz bir hafıza da üretir: altı ay sonra bile 'o gün neden öyle karar verdik' sorusunun cevabı dosyada durur. Kanıt şartı kalkarsa ekip zamanla dedikodu hızıyla çalışmaya başlar; bir gün gerçekten kritik bir iddia kanıtsız kabul edilir, yanlış çıkar ve Budlum gerçek ağa kusurlu bir kararla yürür — bedeli de kullanıcıların parası ve güveni olur.
- A) Kanıt zorunlu kalsın
- B) Kanıt isteğe bağlı olsun
- C) Kanıt gerekmez, güven esastır

## Q6 — Permissionless mimari ve whitelist yasağı
**Teknik:** `STORAGE_OPERATOR`, `RELAYER`, `PROVER`, `VALIDATOR` rolleri `PermissionlessRegistry` ile, stake tabanlı, whitelist/onay yok. `PoaMembershipRegistry` ayrı, B.U.D. asla PoA'ya dokunmaz. (CLAUDE.md §2)
**Non-teknik (herkes için):** Halka açık bir meydanla, kapısında liste olan bir kulüp arasındaki seçim gibi: Budlum'a katılmak isteyen herkesin, kurallara uyup teminatını yatırarak, kimseden izin almadan katılabilmesi ilkesi bu. Bu ilke korunursa dünyanın her yerinden insanlar eşit şartlarda sisteme güç verir; tek bir ülkenin, şirketin ya da kişinin kaprisiyle kimse dışarıda bırakılamaz — Budlum gerçekten ortak bir altyapı olur. Ayrıcalık listesine dönülürse ilk gün belki 'güvenlik' diye sunulur ama zamanla liste sahibi fiilen sistemin sahibine dönüşür; vaat edilen tarafsızlık kaybolur, kullanıcılar bunu fark ettiğinde güven bir daha toparlanamayacak şekilde kırılır.
- A) Permissionless kalsın, whitelist kesinlikle yasak
- B) Whitelist eklenebilir (kurumsal istek)
- C) Sadece davetliler girebilsin

## Q7 — VerifyMerkle production gate (Phase 4 = Z-B Commit 3.5)
**Teknik:** `bud-isa::Opcode::VerifyMerkle=0x1E`, `is_experimental()=false` oldu (önce `true` idi). 1-depth, 2-depth, 64-depth STARK testleri yeşil, `proves_verify_merkle_valid_64_depth` ignore'dan çıkarıldı, BudZero job yeşil. (PHASE0.06_PLAN aslında Phase 0.44)
**Non-teknik (herkes için):** Yıllarca kimsenin çözemediği bir saat kadranını sonunda çalıştırmak gibi: Budlum'un 'dosyayı gerçekten saklıyor musun' sorusuna matematikle kanıt isteme yeteneği artık tam güçle çalışıyor. Bu kapının açık kalması, depolama sözü verenlerin boş konuşamayacağı anlamına gelir; kullanıcının fotoğrafı gerçekten duruyor mu, lafla değil kanıtla belli olur. Kapı geri kapanırsa sistem eski, güvene dayalı haline döner: iyi niyetli herkes sorunsuz yaşar ama tek bir kötü niyetli kişi 'saklıyorum' diyerek hiçbir şey saklamadan para kazanabilir ve skandal patladığında Budlum'un en temel vaadi — verinin gerçekten güvende olması — yara alır.
- A) Gate açık kalsın (mevcut, VerifyMerkle prod'da aktif)
- B) Gate kapalı kalsın (eski, sadece test)
- C) Gate sadece testnet'te açık, mainnet'te kapalı

## Q8 — B.U.D. Faz 3: Merkle proof zorunlu
**Teknik:** `src/domain/storage_deal.rs` `open_deal` artık `merkle_proof: Option<Vec<u8>>` ve `storage_root: Option<Hash32>` zorunlu, `ProofEnvelope` bincode deserialize ile format-validasyon. (Phase 0.10 planı aslında Faz 3)
**Non-teknik (herkes için):** Depoya eşya bırakırken içeridekilerin fotoğrafını çektirip imzalatmak gibi: bir depolama anlaşması açılırken kanıtın peşinen gösterilmesi şart. Bu şart sayesinde 'sonra getiririm' diyen kimse sisteme boş vaatle giremez; anlaşma ilk günden sağlam temele oturur. Şart gevşetilirse ilk haftalar rahat görünür, başvurular artar; ama aylar sonra yapılan ilk ciddi denetimde bazı 'depocuların' aslında hiçbir şey tutmadığı ortaya çıkar ve o ana kadar onlara güvenip dosyasını emanet etmiş herkes mağdur olur — Budlum'un itibarı da onlarla birlikte gider.
- A) Zorunlu kalsın (gerçek Proof-of-Storage)
- B) Opsiyonel kalsın (interim challenge yeterli)
- C) Tamamen kaldırılsın

## Q9 — B.U.D. Faz 4: GlobalBlockHeader.storage_root
**Teknik:** `BlockHeader` / `GlobalBlockHeader` içine `storage_root` eklendi, block hash'e dahil, genesis'te `hash(empty)`. (PHASE0.06_PLAN §4.4)
**Non-teknik (herkes için):** Apartmanın yönetim defterinde her sayfanın kenarına 'bu tarihte depoda şunlar vardı' diye özet bir damga vurulması gibi: Budlum'un ortak kaydında her dilimde tüm depolamanın özeti yer alıyor. Böylece geçmişteki herhangi bir güne dönüp 'o gün verim neredeydi' sorusu kesin ve tartışmasız cevaplanabilir; anlaşmazlıklar lafla değil kayıtla çözülür. Bu özet dışarıda, ayrı bir rafta tutulursa ileride bir uyumsuzluk çıktığında hangi kaydın doğru olduğu tartışma konusu olur ve en kötüsü, kötü niyetli biri iki raftaki farkı kullanarak haksız kazanç sağlayabilir; özette yapılan tek bir çıkarma ise geçmiş sorgulama yeteneğini tamamen öldürür.
- A) storage_root block hash'e dahil kalsın
- B) storage_root ayrı bir sidecar'da tutulsun, block hash'e dahil olmasın
- C) storage_root tamamen kaldırılsın

## Q10 — ConsensusStateV2 migration iskeleti
**Teknik:** `StateSnapshotV2` `schema_version=3`, `registry`, `liveness`, `tokenomics` + atomik `tokenomics_burn` (timed_burn + burn_reserve_address + team_vesting) taşır, `#[serde(default)]` ile eski schema-2 uyumlu, `from_snapshot_v2` atomik restore. (STATUS.md, PHASE0.378)
**Non-teknik (herkes için):** Eski model telefondaki rehberin yenisine taşınması gibi: Budlum'un iç hafızası büyürken eski yedeklerin de yeni sistemde açılabilmesi gerekiyor. Bu köprü sayesinde yarın sistem büyük bir yenileme geçirse bile hiçbir kullanıcının bakiyesi, dosyası ya da geçmişi buharlaşmaz; herkes kaldığı yerden devam eder. Köprü kaldırılırsa bir gün yapılacak mecburi yenilemede ya bazı kullanıcılar dışarıda kalır ya da ekip 'eskiyi kurtarma' paniğiyle aylar kaybeder; en kötü senaryoda kaybolan bir hesap için geri döndürülecek hiçbir yol kalmaz ve bu haber, Budlum'un teknik başarısından daha yüksek sesle konuşulur.
- A) V2 migration iskeleti korunsun, atomik restore şart
- B) V1'e geri dönülsün
- C) Migration otomatik değil manuel olsun

## Q11 — BLS/PQ HSM policy (Phase 0.378 B1)
**Teknik:** `src/crypto/pkcs11.rs` gerçek PKCS#11 HSM, `cryptoki 0.12.0` + `secrecy 0.10.3` (`SecretString`), `MechanismType::new_vendor_defined` fail-closed, `VendorDefinedMechanism::new::<()>()`, `CInitializeArgs::new(OS_LOCKING_OK)`, `EddsaParams::new(Pure)`. Disk `ValidatorKeys` mainnet'te reddedilir. (F1-F10 rapor V14)
**Non-teknik (herkes için):** Ev anahtarını paspasın altında bırakmakla kasada saklamak arasındaki fark gibi: Budlum'u yöneten en kritik anahtarlar yalnızca özel donanım kasasının içinde tutuluyor, sıradan bir dosya olarak bilgisayarda duramıyor. Böyle kalırsa sisteme sızan kötü biri bile anahtarı kopyalayıp götüremez; en fazla o anki oturuma zarar verebilir. Gevşetilirse — 'geliştirme kolay olsun' diye taklidine ya da 'operatör isterse' diye sade dosyaya izin verilirse — bir gün tek bir sızıntı, tüm ağın imza yetkisini ele geçirir; bu noktadan sonra saldırgan Budlum adına her şeyi onaylayabilir ve böyle bir olayın itibar maliyeti, o ana kadarki tüm altyapı yatırımından büyük olur.
- A) Sadece gerçek HSM, disk yasak (mevcut)
- B) Mock HSM de kabul edilsin (geliştirme kolaylığı)
- C) Disk de kabul edilsin (operatör tercihi)

## Q12 — Vendor mechanism CLI wiring (F3)
**Teknik:** `--pkcs11-bls-mechanism` / `--pkcs11-pq-mechanism` `commands.rs:223-226,687-693` parse ediyor, `Pkcs11Signer::with_vendor_mechanisms()` var, `main.rs:485` artık `new()` + `with_vendor_mechanisms()` ile wire edildi. (Rapor F3 fix)
**Non-teknik (herkes için):** Pahalı bir kasa alıp 'kendi özel açma şeklimizi' hiç tanımlamamak gibi olmasın diye: donanım kasasının özel imza yöntemi artık ayarlardan seçilebiliyor. Bu bağlantı sayesinde Budlum, anahtarını en üst düzeyde, üreticinin öngördüğü en güçlü yöntemle kullanabiliyor; yarın daha da güçlü bir yöntem çıkarsa sadece ayar değiştirmek yeterli. Bağlantı geri alınırsa donanım kasası sapasağlam rafta kalır ama hep bilinen sıradan yöntemle kullanılır; bu da ileride kasanın özel korumasına güvenerek plan yapan bir operatörün aslında o korumayı hiç yaşamadığını ancak bir sızıntı anında öğrenmesi riskini doğurur.
- A) Wire kalsın (config → signer)
- B) Wire kaldırılsın, sadece software fallback
- C) Vendor mechanism tamamen kaldırılsın

## Q13 — README roadmap ve test sayısı prose
**Teknik:** Badge otomasyonu `cargo test --lib` sayısını `README.md` içindeki `tests-XX%20lib` rozeti ile otomatik güncelliyor, prose da `531 → 538 → 539 → 546` manuel tazelendi. (F6 fix)
**Non-teknik (herkes için):** Vitrindeki fiyat etiketiyle depodaki sayım listesinin tutması gibi: Budlum'un giriş sayfasında yazan başarı sayısı ile arka planda gerçekten dönen sayı aynı olmalı. Rozet kendiliğinden güncelleniyor, metin elle tazeleniyor; doğru işletilirse ziyaretçi her zaman gerçek tabloyu görür ve ekip de yalan söylemiş durumuna düşmez. İkisi de ihmal edilirse bir gün sayfa yüzlerce adım geriden gelir; dışarıdan biri fark edip bunu duyurduğunda 'acaba başka neleri abartıyorlar' şüphesi doğar ve Budlum gibi güven üzerine kurulu bir projede bu küçük görünen uyumsuzluk, büyük iddiaların da sorgulanmasına yol açar.
- A) Rozet otomatik, prose manuel tazeleme (mevcut)
- B) Prose da otomatik olsun
- C) Test sayısı hiç yazmasın, sadece badge

## Q14 — Persona paketleri (user-devnet/developer/enterprise-poa)
**Teknik:** `config/personas/{user-devnet,developer,enterprise-poa}.toml` + `docs/PERSONAS.md` uyumluluk matrisi, aynı `budlum-core` binary farklı config ile farklı persona. (Phase 0.398)
**Non-teknik (herkes için):** Aynı aracın şehir içi, arazi ve ticari paketlerle satılması gibi: tek bir Budlum programı, sadece ayar dosyası değiştirilerek sıradan kullanıcıya, geliştiriciye ya da büyük kuruma uygun hale geliyor. Bu sayede üç dünya aynı çekirdeği kullanır; birinde bulunan hata hepsinde düzelir, kimse bakımsız bir yan sürümde unutulmaz. Her kitleye ayrı program yapılsaydı kısa sürede üç farklı Budlum doğar, hangisinin güncel ve güvenli olduğu takip edilemez hale gelir ve bir gün kurumsal müşterinin kullandığı sürümün aylardır yama almadığı ortaya çıkar — bu, güvenle imzalanmış bir iş anlaşmasının tam ortasında yaşanabilecek en kötü sürprizdir.
- A) Persona sistemi kalsın
- B) Tek persona yeterli (developer)
- C) Persona sistemi kaldırılsın, herkes aynı config

## Q15 — Prometheus latency histogram wiring (Phase 2 §2.5)
**Teknik:** `src/core/metrics.rs` `Metrics` içinde `chain_height`, `blocks_produced`, `rpc_request_duration` histogram, `/metrics` text encoding test ile doğrulandı (`test_metrics_initialization_and_encoding`).
**Non-teknik (herkes için):** Bir hastanedeki bekleme süreleri panosu gibi: Budlum kendi nabzını sürekli ölçüyor ve isteyenin görebileceği bir ekrana yazıyor. Bu sayede yavaşlama daha kimse şikâyet etmeden fark edilir; 'geçen salı öğleden sonra sistem neden ağırlaştı' sorusunun cevabı tahminle değil kayıtla bulunur. Bu gösterge olmazsa ekip ancak kullanıcılar isyan ettiğinde bir şeylerin ters gittiğini öğrenir ve o ana kadar birikmiş kayıp — kaçan işlemler, soğuyan kullanıcılar, tutulamayan randevular — çoktan gerçekleşmiş olur.
- A) Histogram wiring kalsın
- B) Sadece counter yeterli, histogram kaldırılsın
- C) Metrics tamamen kaldırılsın

## Q16 — Per-IP quota / RPC rate limiting (Phase 2 §2.6)
**Teknik:** `src/rpc/server.rs` `is_per_ip_rate_limited` per-minute pencere, 10k IP bellek tavan, `X-Real-IP` sadece `trusted_proxies` set ise. Test `test_per_ip_rate_limiting` eklendi.
**Non-teknik (herkes için):** Bir dükkâna girip raftaki her şeyi kucaklayıp çıkmaya çalışan müşteriye 'bir seferde üç ürün' kuralı koymak gibi: tek bir kaynaktan yağan istekler belli bir hızın üzerine çıkarsa yavaşlatılıyor. Bu kural sayesinde tek bir kötü niyetli ya da bozuk istemci, herkesin hizmetini kilitleyemez; diğer binlerce kullanıcı hiçbir şey hissetmeden işine devam eder. Sınır kaldırılırsa bir gün tek bir saldırgan ya da hatalı bir uygulama tüm kapıyı tıkar; Budlum'un dış dünyayla konuştuğu pencere saatlerce cevapsız kalır ve basında çıkan tek cümle — 'Budlum erişilemez durumda' — gerçek sebebi kimseye anlatamaz.
- A) Per-IP rate limit kalsın
- B) Sadece global rate limit yeterli
- C) Rate limit tamamen kaldırılsın

## Q17 — Fuzzing + dependency audit + SBOM (Phase 2 §2.7-2.8)
**Teknik:** `fuzz/` (5 target: block_deserialize, consensus_validate, snapshot_deserialize, transaction_deserialize), `cargo audit`, `cargo cyclonedx` SBOM, `scripts/audit-deps.sh`, `scripts/generate-sbom.sh`, CI `supply-chain-extra` job. (Phase 0.40 §1.7)
**Non-teknik (herkes için):** Yeni bir ilacın hem laboratuvarda rastgele dozlarla sınanması hem de içindekiler listesinin bağımsız kurumca doğrulanması gibi: Budlum'un kendi kodu sürekli bozuk veriyle sarsılıyor, içine eklenen hazır parçalar da düzenli kontrolden geçiyor. Bu ikili sayesinde hem kendi yazdığımız hatalar hem de hazır aldığımız parçaların zaafları, kötü niyetli birinden önce bizim radarımıza düşer. Bunlar yapılmazsa tehlike görünmez birikir: bir gün hiç beklenmedik bir girdi sistemi çökertebilir ya da hazır bir parçada çıkan ünlü bir açık, Budlum'un kapısını ardına kadar açar — ve kamuoyu 'neden kontrol etmediniz' sorusunun cevabsız kaldığını görür.
- A) Fuzz + audit + SBOM tam kalsın
- B) Sadece audit yeterli
- C) Hepsi kaldırılsın

## Q18 — Bug bounty programı (Phase 2 §2.9)
**Teknik:** `docs/BUG_BOUNTY.md` kapsam, ödül seviyeleri, iletişim kanalı, immunefi benzeri. Harici audit öncesi bug bounty ile başla (Phase 0.40 §1.5 kararı C).
**Non-teknik (herkes için):** Bir kasa üreticisinin 'bu kasayı açabilene ödül' ilan etmesi gibi: Budlum da açığı bulup bize özelden bildireni ödüllendiriyor. Bu kanal sayesinde dünyadaki binlerce meraklı zihin, düşmanca değil dostça çalışır; zayıf noktayı ayıp olmadan bulan kişi hem para kazanır hem de kullanıcılar hiç zarar görmeden açık kapanır. Bu program olmazsa açığı bulan kişinin önünde iki yol kalır: susmak ya da açığı karanlık pazarda satmak. İkisi de Budlum için felaket senaryosudur; çünkü açık eninde sonunda birinin eline geçer ve o gün gazetedeki haber 'bulan kişi ödüllendirildi' değil 'kullanıcılar soyuldu' olur.
- A) Bug bounty ile başla (mevcut karar)
- B) Doğrudan harici firma audit'i
- C) Hiçbiri, self-audited yeterli

## Q19 — Mainnet genesis config ve fail-closed guard'lar (Phase 3 §3.1)
**Teknik:** `config/mainnet-genesis.json` + `mainnet.toml` + `test_mainnet_genesis_json_matches_code` hash+state_root+validator_set_hash eşitliği, `test_mainnet_genesis_hash_matches_documented_constant` absolute assert `02166d370613fc70e5beb47e4d1ef48e5ccad93eb0f4b8bd5edfe5787a7f98fc`. Placeholder peer guard `first_placeholder_peer` marker listesi `dummy, placeholder, 203.0.113., .example`. (F7, F9)
**Non-teknik (herkes için):** Bir uçağın kalkıştan önce yakıt göstergesini iki kez doğrulaması gibi: Budlum, gerçek ağ için gerekli başlangıç dosyaları tam ve doğru değilse kendini hiç başlatmıyor. Bu kural sayesinde yarım hazırlıkla — sahte adreslerle, eksik tanımlarla — yanlışlıkla 'gerçek ağdaymış gibi' çalışan bir sistem asla doğmaz. Kural gevşerse bir gün ekipten biri yanlış dosyayla ağı başlatır ve fark edilene kadar üretilen her şey çöp olabilir; daha kötüsü, sahte bir başlangıç noktasıyla çalışan ağ kullanıcılardan gerçek para toplar ve sonra 'baştan başlıyoruz' demek zorunda kalınır — bu cümle bir daha asla unutulmaz.
- A) Fail-closed guard'lar kalsın (mevcut)
- B) Guard'lar uyarı versin ama devam etsin (fail-open)
- C) Guard'lar kaldırılsın

## Q20 — Docker + systemd + runbook (Phase 3 §3.2-3.3)
**Teknik:** `Dockerfile`, `docker-compose.yml`, `docs/operations/PRODUCTION_RUNBOOK.md` §8 genesis hash tablosu, `operations/VALIDATOR_ONBOARDING.md`, `NETWORK_HARDENING.md`, `ARCHIVE_AND_BACKUP.md`.
**Non-teknik (herkes için):** Bir lokantanın hem mutfak kuralları kitabı hem de 'tesadüfen açılınca da çalışsın' otomasyonu gibi: Budlum'un nasıl kurulacağı, nasıl servis halinde çalışacağı ve arıza durumunda kimin ne yapacağı yazılı ve paketlenmiş durumda. Bu paket sayesinde yeni bir operatör bile sistemi saatler içinde ayağa kaldırabilir; bilgi bir kişinin kafasında değil, herkesin elinde durur. Bu yoksa sistemi kuran tek kişi hastalansa tüm operasyon felç olur; gece üçte yaşanan bir arızada kimse telefonun ucundaki kişinin yarım hatırladığı komutlara bel bağlamak zorunda kalmaz — kalırsa da o gece alınan tek yanlış karar, ertesi gün telafisi olmayan bir veri kaybına dönüşebilir.
- A) Docker+systemd+runbook tam kalsın
- B) Sadece binary yeterli, docker kaldırılsın
- C) Hepsi kaldırılsın

## Q21 — Network hardening (Phase 3 §3.4)
**Teknik:** `src/network/` p2p max_peers, peer_rate_limit_per_minute, `peer_manager` token bucket, banned_peers persist, mdns_enabled false mainnet, `PeerManager` security config. (Q5 guard)
**Non-teknik (herkes için):** Bir sitenin kapısına hem kamera hem turnike hem de tanımadık araçları kaydeden güvenlik kulübesi koymak gibi: Budlum'un dış dünyayla konuştuğu ağ katmanı pek çok ufak ama ciddi korumayla sertleştirildi. Bu sayede kabaca doldurma, oyalama ve kandırma taktikleriyle gelen saldırılar daha kapıda boşa çıkar; ağın gerçek işi sakin sakin yürür. Sertleştirme olmadan internet açık denizdir: ilk ciddi fırtınada kapılar kapanır, kullanıcılar dışarıda kalır ve 'güvenliği sonra yaparız' diyen erteleme kararının faturası, sistemin tam da büyümeye başladığı haftada kesilir.
- A) Hardening tam kalsın
- B) Sadece max_peers yeterli
- C) Hardening kaldırılsın

## Q22 — Validator onboarding flow (Phase 3 §3.5)
**Teknik:** `src/registry/permissionless.rs` stake == registration, `sync_validator_registration`, `upsert_stake`, `bond_relayer`, `bond_prover`, `bond_storage_operator`, RPC `bud_registryRegister`, `bud_registryBondRelayer/Prover`, `bud_registryActiveMembers`. (CLAUDE.md)
**Non-teknik (herkes için):** Bir kooperatife üye olmak gibi: isteyen herkes teminatını yatırır ve otomatik olarak Budlum'un işleyişinde görev almaya hak kazanır; ne mülakat ne torpil ne bekleme listesi var. Bu akış sayesinde ağ büyüdükçe yönetim de doğal büyür; yeni güç, eskilerin izni olmadan sisteme katılır ve tekelleşme engellenir. Kayıt kapı elle tutulursa ilk başta kalite kontrol gibi görünür; fakat zamanla 'kim girer' kararını veren küçük grup fiili bir yönetim kuruluna dönüşür ve Budlum'un en büyük vaadi olan kimsesiz-izinsiz katılım sessizce ölür — bunu fark eden dış dünya projeyi bir daha aynı gözle görmez.
- A) Stake==registration kalsın
- B) Ayrı manual kayıt adımı eklensin
- C) Sadece PoA whitelist ile validator olunur

## Q23 — B.U.D. interim retrieval challenge dokümantasyonu (Phase 3 §3.6)
**Teknik:** `docs/BUD_INTERIM.md` interim challenge sadece byte-range testi, gerçek Proof-of-Storage değil, `RetrievalChallenge`/`Response`/`Outcome` interim, Faz 3 gerçek PoS için VerifyMerkle açık. (Faz 2 compat)
**Non-teknik (herkes için):** Bir müteahhidin binayı bitirmesine rağmen yangın merdivenini 'geçici' tabelasıyla bırakması gibi: Budlum'da depocunun gerçekten elinde veri tutup tutmadığını ölçen tam denetim henüz geçici bir kontrolle idare ediliyor ve bu, belgede açıkça ilan ediliyor. Dürüst ilan sayesinde kimse kendini tam korunuyor sanmıyor; herkes geçici düzenin sınırlarını bilir ve nihai denetim gelene kadar riskini ona göre ayarlar. İlan kalkar ya da geçici düzen 'kalıcı' gibi sunulursa bir gün kötü niyetli bir depocu geçici kontrolün açığından yararlanıp hiç emek harcamadan kazanç sağlar; skandal patladığında kimse 'biz zaten biliyorduk' savunmasını kullanıcılara anlatamaz.
- A) Interim challenge dokümante kalsın, gerçek PoS Faz 3'te
- B) Interim challenge kaldırılsın, direkt gerçek PoS
- C) Interim challenge gerçek PoS gibi pazarlansın

## Q24 — B.U.D. Faz 5 economics accounting (Phase 1 devamı)
**Teknik:** `Blockchain::accrue_storage_operator_rewards` (fee_per_epoch * epochs), `finalize_missed_storage_challenges` slashed bond total + burned, `StorageEconomicsEvent` + `ChainHandle::get_storage_economics_events/summary`, ChainActor otomatik bakım (block üretim/doğrulama sonrası reward accrual + challenge issuance + missed finalization).
**Non-teknik (herkes için):** Bir lojistik şirketinde şoförlerin kazandığı primlerin ve yediği cezaların her gün deftere işlenmesi gibi: Budlum'da depo hizmeti verenlerin hak edişleri ve kabahatleri de otomatik olarak kayıt altına alınıyor. Bu defter sayesinde 'bana hakkım verilmedi' diyen biri elle tutulur kayda bakar; kimseye söz geçmez, kayıt konuşur. Kayıt tutulmazsa bir gün ödeme günü kavgaya döner: biri fazla iddia eder, biri eksik hissettiğini söyler, hakem yoktur; topluluk içinde ilk büyük kavga genellikle para dağıtımındandır ve Budlum gibi ortak mülkiyet rüyası gören bir proje, kendi içinde adaletsizlik dedikodusuyla yıpranmamalıdır.
- A) Economics accounting tam kalsın
- B) Sadece reward, slashing olmasın
- C) Economics tamamen kaldırılsın

## Q25 — Constitution §1: Content & Moderation — Community Voting
**Teknik:** Reported content validator/governance oylaması ile. (BUDLUM_CONSTITUTION.md §1)
**Non-teknik (herkes için):** Bir mahalledeki duyuru panosuna asılan tartışmalı ilan için bütün mahallelinin oy kullanması gibi: Budlum'da sakıncalı bulunan içerik hakkında kararı tek bir şirket değil, topluluğun seçilmiş gözcüleri veriyor. Bu modelde hiçbir tek kişi kendi zevkine göre sansür yapamaz; kararın arkasında bir topluluk iradesi ve yorumlanabilir bir süreç vardır. Tek elden karar verilseydi ilk günler hızlı ve sorunsuz görünürdü; ama ilk tartışmalı vakada 'kim bu adam da karar veriyor' sorusu sorulur, ertesinde siyasi baskılar kapıyı çalar ve Budlum hem özgürlükçülerin hem de düzenleyicilerin hedefinde, iki ateş arasında kalır.
- A) Community voting kalsın
- B) Merkezi moderasyon olsun
- C) Hiç moderasyon olmasın

## Q26 — Constitution §1: Right to be Forgotten — Hard Pruning (F1)
**Teknik:** `NftBurn` transaction ile linked B.U.D. data fiziksel silinir, `NftRegistry::burn` cid döndürür, `StorageRegistry::prune_content(cid,epoch)` deal'leri expired yapar manifest'i siler, `NodeCommand::StoragePrune{cid:[u8;32]}` + `ContentStore::delete` fiziksel chunk silme, `NetworkMessage::StoragePrune` gossip ile full P2P (Q-X1 full_p2p_prune). Log `Hard Prune Triggered` dürüstleştirildi. (F1 fix 5322e00 + b65f058)
**Non-teknik (herkes için):** Bir fotoğrafçıya verdiğiniz negatifi geri isteyip yakılmasını seyretmek gibi: Budlum'da bir belgenin sahipliğini iptal ettiğinizde veri gerçekten fiziksel olarak silinir — sadece üstü çizilmez, depolarda izi kalmaz. Bu özellik hem yasaların 'unutulma hakkı' dediği şeyin teknik karşılığıdır hem de bir gün bir mahkeme ya da mağdur 'bunu kaldırın' dediğinde 'yapabiliyoruz' cevabını verebilmenin tek yoludur. Gerçek silme olmasaydı Budlum söz verdiği tek şeyi — kullanıcının kendi verisi üzerindeki son sözü — tutamaz hale gelirdi; ve hem yasal sorumluluk doğar hem de 'silindi' denen kayıtların bir sunucuda yüzdüğü ortaya çıktığı gün, güven bir kalemde tükenir.
- A) Hard pruning tam P2P (consensus+local+network broadcast) kalsın
- B) Sadece registry silme yeterli, fiziksel silme olmasın
- C) Hard pruning tamamen kaldırılsın

## Q27 — Constitution §1: Content Portability
**Teknik:** NFT transferinde content otomatik yeni sahibin profiline ve SocialFi feed'ine taşınır, `ownership` map güncellenir. (Constitution §1, RD_SOCIALFI)
**Non-teknik (herkes için):** Bir tabloyu sattığınızda tablonun o alıcının evine taşınması gibi: Budlum'da sahiplik belgesi el değiştirdiğinde o belgeye bağlı içerik de otomatik olarak yeni sahibinin vitrinine geçer. Bu sayede ikinci el piyasası canlı kalır: alan kişi gerçekten 'şeyi' alır, sadece kağıt üzerinde bir numara değil. Taşıma olmasa alıcının elinde boş bir sertifika kalır, satıcı hâlâ içeriği sergilemeye devam eder ve pazaryeri 'satın aldığım şeyin bende görünmemesi' şikâyetleriyle dolar; kısa sürede kimse platformda bir şey satın almak istemez ve ekonomi doğmadan ölür.
- A) Portability kalsın
- B) Transferde içerik eski sahibinde kalsın
- C) Transfer yasak olsun

## Q28 — Constitution §2: Social Recovery — No recovery
**Teknik:** HSM key kaybolursa account ve data sonsuza kadar kilitli, recovery yok, maximum security. (Constitution §2)
**Non-teknik (herkes için):** Bir kasanın tek anahtarını kaybedince içindekilerin sonsuza dek içeride kalması gibi: Budlum'da erişim anahtarını kaybeden kişi için geri dönüş kapısı yok — ne bir 'şifremi unuttum' bağlantısı, ne de çağrı merkezi. Bu katı kural, hiç kimsenin — ekibin bile — sizin yerinize hesabınıza girememesi anlamına gelir; güvenlik budur ve bedeli de budur. Geri dönüş kapısı eklenseydi ilk hafta mutlu haberler gelirdi; ama o kapı aynı zamanda sosyal mühendislerin, sahte mahkeme kararlarının ve sabırlı dolandırıcıların hedefi olurdu ve ilk başarılı saldırıda biri, başkasının yıllarının birikimini tek telefonla boşaltırdı — o günden sonra 'güvenli' kelimesi Budlum için bir daha kullanılamazdı.
- A) No recovery kalsın (max güvenlik)
- B) Social recovery eklensin (arkadaşların kurtarsın)
- C) Merkezi recovery (email ile)

## Q29 — Constitution §2: BNS Disputes — First Come First Served
**Teknik:** `.bud` isim hakları kayıt anında absolute, trademark arbitration yok, `BnsRegistry` first-come. (Constitution §2)
**Non-teknik (herkes için):** Eski kovboy filmlerindeki arazi tescil yarışı gibi: Budlum'da bir adı önce kaydettiren alır; sonra gelen 'benim markamdı' dese bile sistem laf dinlemez. Bu katı sıra kuralı sayesinde kimse arkadan dolanamaz, pazarlık açılmaz, hakem kavgası çıkmaz; herkes baştan kuralı bilir ve konumunu ona göre alır. Hakemlikli sistem olsaydı ilk ünlü ismin talebiyle büyük bir kavga başlardı: kim 'ilk' sayılacak, kimin tanınmışlığı 'daha haklı'? Bu kapı bir kez açılırsa her ünlü marka kendi lobisiyle gelir ve Budlum bir kayıt defterinden çok bir dava mahkemesine dönüşür — enerjisi isim kavgalarına gider, ürüne değil.
- A) First come first served kalsın
- B) Trademark arbitration eklensin
- C) İsimler açık artırmayla satılsın

## Q30 — Constitution §2: Privacy — Selective Encryption
**Teknik:** Her SocialFi post için kullanıcı Public veya Encrypted seçer. (Constitution §2)
**Non-teknik (herkes için):** Bir mektubu zarfa koyup koymayacağınıza her seferinde kendinizin karar vermesi gibi: Budlum'da her paylaşımınız için o an seçersiniz — herkes okusun mu, yoksa sadece anahtarı verdiğiniz kişiler mi? Bu seçenek sayesinde aynı kişi hem meydanda konuşabilir hem de fısıldayabilir; platform sizi tek kalıba zorlamaz. Tek tip zorunluluk olsaydı ya herkesin her şeyi açıkta kalır — mahremiyet biter, insanlar çekinir, platform ölür; ya da her şey kapalı kalır — kamusal sohbet biter, mahalle meydanı bomboş kalır ve yine platform ölür.
- A) Selective encryption kalsın
- B) Her şey public olsun
- C) Her şey encrypted olsun

## Q31 — Constitution §3: Spam Protection — Fee per post
**Teknik:** Her SocialFi etkileşimi (NftMint) tx fee içerir, `tx.fee` saturating_sub. (Constitution §3)
**Non-teknik (herkes için):** Şehir meydanına ilan asmak için küçük bir pul ücreti alınması gibi: Budlum'da her paylaşımın ufak bir bedeli var. Bu bedel sayesinde bir gecede milyon tane anlamsız mesaj basıp ortamı çöpe çevirmek isteyen biri, cebinden gerçek para ödemek zorunda kalır ve hesabı tutmaz; dolayısıyla sizin akışınız temiz kalır. Bedel sıfır olsaydı ilk ay herkes sevinirdi; ama saniyeler içinde reklam yağmurları, sahte kampanyalar ve bot orduları her köşeyi kaplardı, gerçek insanlar birbirini bulamaz hale gelirdi ve platform, en değerli kaynağı olan insan dikkatini tek seferde tüketirdi.
- A) Fee per post kalsın
- B) Ücretsiz gönderi
- C) Aylık abonelik

## Q32 — Constitution §3: Longevity — Permanent by default
**Teknik:** Data NFT yakılana kadar ağda kalır, `DealStatus::Active` → `Expired` sadece `deal_end_epoch` veya `burn` ile. (Constitution §3)
**Non-teknik (herkes için):** Bir fotoğrafı aile albümüne koymak gibi: Budlum'a bir kez bıraktığınız kayıt, siz özellikle silmedikçe orada kalır; bir şirketin keyfiyle ya da sunucu faturası yüzünden buharlaşmaz. Bu vaat, anılarını ve işlerini emanet eden insanlara 'yarın da burada olacak' der ve Budlum'a olan bağı ilk yıldan itibaren kalınlaştırır. Kalıcılık garantisi olmasaydı herkes bir gün verisinin yok olacağı korkusuyla yaşar, kimse gerçekten önemli şeyini emanet etmezdi; böyle bir platform yalnızca geçici sohbet yeri olur ve on yıl sonrasına eser bırakma hayali kuran Budlum'un ruhu ölürdü.
- A) Permanent by default kalsın
- B) 1 yıl sonra otomatik silinsin
- C) Kullanıcı süre seçsin

## Q33 — Constitution §3: Self-Hosting Option
**Teknik:** Kullanıcı yıllık storage rent ödemek istemezse local B.U.D. node ile self-host edebilir, `MobileConfig` batarya/Wi-Fi dostu, `ShardManager` self-host önceliği. (Constitution §3, Phase 5 §5.2)
**Non-teknik (herkes için):** Evdeki kiler dolabını kendin tutmakla marketin deposuna kira ödemek arasındaki seçim gibi: isteyen kullanıcı, dosyalarını kendi cihazında saklayarak dışarıya tek kuruş ödemeden de Budlum'da yaşayabiliyor. Bu seçenek hem parası olmayana kapıyı açık tutar hem de 'verim başkasının elinde' diye endişelenenlere gerçek bir alternatif sunar. Bu yol kapatılsaydı sistem kaçınılmaz olarak 'var olanı daha da güçlendiren' bir yapıya döner: kirayı ödeyebilen kalır, ödeyemeyen gider; zamanla Budlum, kuruluş vaadi olan geniş katılım hayalinden uzaklaşır ve topluluk bunu affetmez.
- A) Self-hosting seçeneği kalsın
- B) Sadece profesyonel operatörler saklasın
- C) Self-host yasaklansın

## Q34 — Constitution §3: Rewards — Storage Provider Heavy
**Teknik:** Yeni $BUD ihracının çoğunluğu B.U.D. operatörlerine (Storage Proofs), `accrue_storage_operator_rewards` + `pending_bud_boost_share` ağırlıklı dağıtım. (Constitution §3)
**Non-teknik (herkes için):** Bir kooperatifte kârın en büyük payının fiilen yükü taşıyan depo işçilerine verilmesi gibi: Budlum'un yeni ürettiği paranın çoğu, dosyaları gerçekten saklayıp hizmet verenlerin cebine gidiyor. Bu dağılım sayesinde sistemin bel kemiği olan depocular yıllarca sadık kalır; onlar kazandıkça yeni depocular gelir ve ağ güvenle büyür. Ödül dengesi ters kurulsaydı — masa başındakiler kazanıp sahada disk döndürenler az alsaydı — kısa sürede kimse bu zahmetli işe girmez, saklanan dosyalar sahipsiz kalır ve bir gün kullanıcılar 'dosyam nerede' diye sorduğunda cevap verecek depocu bulunamazdı.
- A) Provider heavy kalsın
- B) Validator heavy olsun
- C) Eşit dağıtım

## Q35 — Constitution §3: Advertising & Highlighting Model — 4/16/80 split (F4)
**Teknik:** `NftBoost {nft_id, amount}`: `bud_share=4%`, `creator_share=16%`, `protocol_share=80%`. Executor'da `pending_bud_boost_share+=bud_share`, `creator.balance+=creator_share`, `protocol_share` burn_reserve/treasury'ye (treasury_pool) veya burn. Blockchain'de `distribute_bud_boost_share` fee_per_epoch ağırlığına göre + dust ilk operatöre. (F4 fix 5322e00, 7f054d7, 6dd66e5 config-driven treasury)
**Non-teknik (herkes için):** Bir sokak sanatçısının önüne konan şapkaya para atılması ve bu paranın paylaşılması gibi: Budlum'da bir içeriği öne çıkarmak isteyen para koyar; bunun küçük bir kısmı veriyi taşıyan depoculara, daha büyük bir kısmı içeriğin yaratıcısına, büyük çoğunluğu ise ortak kasaya gider. Bu paylaşım herkesin kazanmasını sağlar: yaratıcı emeğinin karşılığını alır, depocu hizmeti karşılığını alır, topluluk ortak havuzu büyür. Paylaşım dengesiz kurulsaydı — örneğin her şey merkeze gitseydi — yaratıcılar platformu terk eder, depocular ilgisiz kalır; ya da her şey yaratıcıya gitseydi ortak kasa boşalır ve yol, bakım, güvenlik gibi kimsesiz işler fon bulamaz hale gelirdi — reklamsız bir vitrinle satış olmaz, fonsuz bir sistemle de yarın olmaz.
- A) 4/16/80 kalsın (mevcut, weighted + dust first)
- B) 10/30/60 olsun
- C) %100 creator'a gitsin
- D) %100 yakılsın
- E) %4 B.U.D. + %16 creator + %80 yeni ayrı TREASURY_ADDRESS (config'den)

## Q36 — Constitution §3: Treasury & %80 Ekip Havuzu (Q-X4)
**Teknik:** Protocol_share %80 ekip havuzu, `burn_reserve_address` veya yeni `TREASURY_ADDRESS` (config `table treasury { address=... }`), multi-sig single/governance, RPC `bud_treasuryBalance` yok/olsun, event emit. (Q-X4 treasury_pool)
**Non-teknik (herkes için):** Bir mahalle derneğinin kasasının anahtarını kimin tutacağına karar vermek gibi: Budlum'da öne çıkarma ücretlerinden toplanan büyük pay ortak fona akıyor ve bu soru, o fonun hangi hesapta, kimin onayıyla, nasıl yönetileceğini belirliyor. Doğru yapı kurulursa yıllar içinde biriken bu fon yol yapar, okul yapar, yangını söndürür; topluluk 'bizim paramız işe yarıyor' hisseder ve sahiplenme derinleşir. Yanlış kurulursa — tek bir imzaya emanet edilirse ya da adressiz bir boşluğa akarsa — ya bir gün paranın buharlaştığı haberi gelir, ya da kimseye hesap sorulamaz; ve topluluk bir kez 'biz sadece seyirciydik' hissederse, o his bir daha geri dönmez.
- A) burn_reserve_address treasury olarak kullanılsın
- B) Yeni ayrı TREASURY_ADDRESS tanımla, config'den okunur
- C) team_vesting adresi kullanılsın
- D) %80 direk yakılsın, treasury yok
- E) %80 + %4 operatör yoksa tamamı treasury'ye

## Q37 — Constitution §3: Social Ranking — Luminance (Işık Şiddeti)
**Teknik:** NFT `luminance=1000 mcd` (1 cd) başlar, `NftUpdateLight {delta_mcd}` owner-only, +0.0006 cd >30s view, +0.005 cd 5/5 spark, -0.0006 <1s, -0.003 darken, %10 yıllık decay, UI threshold 0.1 cd. (Constitution §3, RD_SOCIALFI)
**Non-teknik (herkes için):** Bir sahnedeki ışığın, alkış arttıkça parlaklaşması gibi: Budlum'da bir içeriğin görünürlüğü, gerçek ilginin geldiği kadar güçlenir. Bu sayede sahne suni şişirmelere değil gerçek alkışa göre aydınlanır; el feneriyle kendi kendine ışık tutan biri kalabalığın alkışını satın alamaz. Basit bir sayaç uygulansaydı robotlar gece yarısı milyon tık üretip sabah herkesin vitrininde sahte yıldızlar parladı; gerçek insanlar haksızlığa uğradığını hisseder, platformun 'yükselme' vaadi çöker ve herkes sessizce evine döner.
- A) Luminance algoritması kalsın
- B) Sadece beğeni sayısı kullanılsın
- C) Ranking tamamen kaldırılsın

## Q38 — Constitution §3: Content Mobility — Digital Bud
**Teknik:** NFT'ler "Dijital Tomurcuk", transfer ile authority ve future earnings yeni sahibe geçer, `transfer(id, from, to)` ownership map günceller. (Constitution §3)
**Non-teknik (herkes için):** Bir çiçeğin sahibi değişince bakım görevinin de yeni sahibine geçmesi gibi: Budlum'da taşınabilir bir değer el değiştirdiğinde onu yaşatma sorumluluğu da yeni sahibiyle yoluna devam eder. Bu sayede hiçbir eser sahibinden ayrıldıktan sonra bakımsız kalmaz; topluluk koleksiyonu canlı ve yürür bir bahçe gibi kalır. Kural olmasa sistem sahiplerinin unuttuğu öksüz kayıtlarla dolar; bir süre sonra kimse hangi içeriğin kime ait olduğunu takip edemez hale gelir ve o güzelim ortak bahçe, bakımsız bir mezarlık gibi görünmeye başlar.
- A) Digital Bud mobility kalsın
- B) Transferde earning eski sahibinde kalsın
- C) NFT'ler transfer edilemesin (soulbound)

## Q39 — Constitution §3: Interoperability — Universal Bridge Hub
**Teknik:** Unified ecosystem interface, `HubRegistry`, `budget hub_register`, `Universal Relayer` master translator, EVM, Solana vb. (Constitution §4, Phase 6)
**Non-teknik (herkes için):** Farklı ülkelerin postanelerinin tek bir merkez şubeye kaydolması gibi: başka ağlarda yaşayan uygulamalar, Budlum ile tek kapıdan tanışıyor. Bu merkez sayesinde her yeni bağlantı tek tek öğrenmek zorunda kalmaz; bir kez tanışan taraflar, aynı protokolle konuşmaya devam eder ve dünya ile bağlantı kurmak Budlum için doğal hale gelir. Tek merkez olmasaydı her yeni tanışma özel anlaşma gerektirirdi; ürün ekibi teknoloji yerine pazarlıkla zaman harcardı, her kapı farklı anahtar isterdi ve en muhtemel dış bağlantılar 'sonra yapalım' diye ertelenip Budlum'un dünyaya açılan kapısı uzun süre kapalı kalırdı.
- A) Hub açık kayıt (democratic) kalsın
- B) Hub sadece davetliler
- C) Hub kaldırılsın

## Q40 — Constitution §3: Zero-Fee Inbound Bridge
**Teknik:** Budlum'a inbound transferde upfront $BUD yok, kaynak zincir veya relayer fee gelen varlıktan düşer, `Zero-Fee Inbound Bridge` (Constitution §3)
**Non-teknik (herkes için):** Bir limana gelen geminin yükünü indirirken gümrük vergisi yerine boşaltmayı yapan firmadan küçük bir komisyon alınması gibi: Budlum'a dışarıdan varlık getiren kişi, elinde yerel para olmasa bile endişelenmez; işlem, gelen değerin içinden karşılanır. Bu incelik, kapıyı ilk günden son kullanıcıya açar: kimse 'önce şu parayı almam lazım' diye geri dönmemez; ilk adım acısız atılır. Bu kolaylık olmasaydı sadece önceden hazırlıklı azınlık kapıdan geçebilirdi; meraklı yüzbinler daha eşikte döner ve Budlum, büyüme eğrisinin en kritik haftalarını kaybederdi — sonra o eğriyi geri kazanmak, ilk seferde doğru karşılamaktan on kat pahalıya çıkardı.
- A) Zero-fee inbound kalsın
- B) Inbound için de $BUD gerekli olsun
- C) Inbound tamamen yasak

## Q41 — Constitution §4: Relayer Incentives
**Teknik:** Relayer'lar protokol tarafından $BUD mint ile ödüllendirilir, inbound bridge'de gelen varlığın küçük kısmı fee olarak alır. (Constitution §4, relayer_liveness.rs)
**Non-teknik (herkes için):** Bir kargo şirketinde paketi kapıdan kapıya taşıyan kuryenin her teslimatta pay alması gibi: Budlum'da mesajları ve varlıkları bir dünyadan diğerine taşıyan aracılar da emekleri karşılığında ödüllendiriliyor. Bu teşvik sayesinde hep birileri nöbette olur; mesajlar kuyrukta beklemez, önemli transferler göçebe arama ilanı gibi boşlukta dolanmaz. Teşvik olmasa bu zahmetli işi ilk gün iyilik olsun diye yapacak birileri çıkar; ama ikinci hafta sıkıcı gelir, üçüncü hafta kimse kalmaz ve birinin acil transferi günlerce bekler — platform 'çalışan' değil 'söz veren' bir sisteme dönüşür ve söz, eninde sonunda tükenir.
- A) Relayer mint reward + asset fee kalsın
- B) Sadece mint reward
- C) Sadece asset fee

## Q42 — Constitution §5: AI Layer — Permissioned & Monetized
**Teknik:** `AiOfferData`, `AiPurchaseData` transaction tipleri, user-to-AI data market, explicit permission + payment in $BUD. (Constitution §5, RD_SOCIALFI Q3)
**Non-teknik (herkes için):** Bir marangozun atölyesine gelen firmaya 'bu kapıyı istersen sana da yaparım, ücreti şu' diye fiyat listesi verebilmesi gibi: Budlum'da veri ve hizmetlerini yapay zekâ kullanıcılarına açmak isteyen kişiler, bunun iznini ve bedelini kendileri belirliyor. Bu düzen sayesinde emek sahibi sömürülmeden gelir kazanır; ilgilenen alıcı da karanlık kanallar yerine tek resmi pencereden adil fiyata ulaşır. İzin ve fiyat mekanizması olmasaydı iki yol kalırdı: ya herkesin verisi izinsiz kazınır ve topluluk 'bizi soydular' diye isyan eder; ya da kimsenin verisi hiçbir yere ulaşamaz ve Budlum'un en değerli bilgi zenginliği, hiçbir zaman gelire ve bilgiye dönüşemez.
- A) Permissioned & monetized kalsın
- B) AI erişimi ücretsiz ve açık olsun
- C) AI erişimi tamamen yasak

## Q43 — Constitution §6: Physical Hardware — Plug & Play storage
**Teknik:** $BUD ile satın alınan pre-configured physical nodes, mobile high-priority storage node. (Constitution §6)
**Non-teknik (herkes için):** Evdeki buzdolabını prize takınca mutfağa katkı vermeye başlaması gibi: Budlum'da depolama cihazı alan biri, onu kutusundan çıkarıp bağladığı anda ağa hizmet sunmaya başlayabiliyor. Bu sayede ağ, sadece uzmanların kurabildiği soğuk bir makine değil, sokaktaki herkesin dahil olabileceği sıcak bir hizmet noktasına dönüşür. Kurulum karmaşık olsaydı sistem ancak profesyonel kurumların elinde kalırdı; bu da hem maliyeti yükseltir hem de tek bir ülkeye, tek bir şirkete bağımlılık riskini büyütürdü — büyük bir kriz anında o tek kurum çekilse, Budlum'un depoları yok olurdu.
- A) Physical node satışı kalsın
- B) Sadece yazılım, donanım yok
- C) Donanım zorunlu olsun

## Q44 — Constitution §7: Verified Status & Sub-BNS & Emergency Halt
**Teknik:** Premium BNS yıllık yüksek ödeme ile Verified badge, sub-domains parent-controlled (x.ayaz.bud), DAO Halt topluluk oylaması ile chain'i geçici durdurabilir, $BUD ile storage access boost. (Constitution §7)
**Non-teknik (herkes için):** Bir apartmanda hem güvenlik kamerası rozeti, hem çocuklara ayrı anahtar, hem de yangında elektriği kesme düğmesi olması gibi: Budlum'da doğrulanan kişilere işaret veriliyor, büyük ailelerin küçükleri için bağlı hesaplar açılabiliyor ve gerçek bir felakette sistemi duraklatma imkânı bulunuyor. Bu üç koruma; dolandırıcıyı işaretler, aileleri rahatlatır ve en kritik saatte, kriz büyümeden yangını kesme şansı verir. Bunlar olmasa ilk dolandırıcılık vakasında insanlar kimin gerçek kimin sahte olduğunu karıştırır, çocukların hesapları yönetilemez hale gelir ve bir gece yaşanan sistem krizi, kimse durduramadığı için sabaha kadar büyür — o sabah gazetenin manşeti 'sistem durdurulamadı' olur ve o cümle, o güne kadar yazılan tüm kodun üzerine gölge düşürür.
- A) Hepsi kalsın (premium verified, parent sub-BNS, DAO halt, boost)
- B) Sadece verified kalsın
- C) Hiçbiri olmasın

## Q45 — Phase 2 §2.3: ConsensusStateV2 migration hook
**Teknik:** `Blockchain::collect_block_transactions` + `apply_block_effects` + snapshot V2 → V3 migration test `test_snapshot_v2_migration_roundtrip_with_tokenomics_burn`. (ARENA1 5548c42)
**Non-teknik (herkes için):** Eski bir kasanın içindeki altınları yeni, daha büyük bir kasaya taşırken her adımın tek tek imzalanması gibi: Budlum kendi iç yapısını büyütürken, eski kaydın yeni yapıya sorunsuz aktarıldığından emin olmak için hazırlanmış bir köprü prosedürü bu. Bu kancada her şey yolunda giderse kullanıcı hiçbir şey hissetmez; bir sabah uyanır ve sistemi yenilemiş olur. Köprü gevşer ya da atlanırsa en ufak bir uyumsuzluk bir sabah 'bakiyem gözükmüyor' paniğine döner; bunun ardından gelen destek telefonları, geri alma telaşı ve iki gün sonra çıkan 'veri kaybı iddiası' haberleri, yıllarca özenle biriktirilmiş güveni tek haftada eritebilir.
- A) Migration hook testli kalsın
- B) Migration manuel olsun
- C) Migration kaldırılsın, sıfırdan genesis

## Q46 — Phase 2: Multi-validator permissionless E2E (5548c42)
**Teknik:** `src/tests/permissionless_e2e.rs` 3 validator (v1,v2,absentee) stake→register, çoklu epoch blok üretimi, absentee liveness slashing döngüsü.
**Non-teknik (herkes için):** Bir tiyatro oyununu sahne önünde değil, gerçek seyirciyle prova etmek gibi: Budlum üç bağımsız doğrulayıcının karşılıklı haberleştiği, hiçbirinin torpil geçmediği tam bir deneme sürümünü baştan sona çalıştırdı. Bu prova sayesinde 'kağıt üstünde çalışır' ile 'gerçekte çalışır' arasındaki uçurum kapandı; gerçek ağda ilk gün yaşanması muhtemel şaşkınlıklar önceden görüldü. Bu prova yapılmasaydı ilk ciddi test, gerçek paranın uçtuğu açılış gününde yapılırdı — ve sahne, seyircinin önünde çökerdi; bir daha da 'ikinci ilk gün' olmazdı.
- A) Multi-validator E2E kalsın
- B) Sadece single-validator E2E yeterli
- C) E2E testler kaldırılsın

## Q47 — Phase 2: Liveness — liveness_max_missed_epochs = 20 (38adeec)
**Teknik:** `RegistryParams::default()` içinde `liveness_max_missed_epochs` 10'dan 20'ye çıkarıldı, transient network blip toleransı için mainnet kararı. (ARENA1 13:15 UTC)
**Non-teknik (herkes için):** Bir çalışana 'geç kalırsan hemen işten çıkarılmazsın ama yirminci tekrarında yaptırım uygulanır' demek gibi: Budlum, gözcüsü arada bağlantı kaybederse hemen cezalandırmıyor; ama sabır belli bir sınırın ötesine taşarsa harekete geçiyor. Bu ölçü, normal hayattaki aksaklıkları — elektrik kesintisi, internet arızası, taşınma — affederken sistemli vurdumduymazlığı affetmez; ne gözcü korku içinde yaşar ne de sistem sahipsiz kalır. Sınır olmasa iki kötü uç var: ya her küçük aksaklıkta cezalar yağar ve kimse gözcülüğe cesaret edemez; ya da sonsuza kadar hoşgörü sürer ve bir gün gerçekten sorumsuz bir gözcü, tam hayati bir anda görevini unutur — o anın maliyeti, birikmiş tüm ufak aksaklıkların toplamından ağır basar.
- A) 20 epoch kalsın (mevcut mainnet kararı)
- B) 10 epoch'a geri dön
- C) 5 epoch daha katı olsun
- D) Liveness slashing tamamen kapatılsın

## Q48 — Tokenomics — Vesting cliff/duration ve BUD_UNIT 6 decimals
**Teknik:** `src/tokenomics/mod.rs` `BUD_UNIT=1_000_000` (6 ondalık), `VestingSchedule::unlocked_at` linear from start, cliff anında `total*cliff/duration` açılır (örn. 60 epoch cliff, 200 duration → 250e9). Test `bud(1_000_000)/4` kilitli. (ARENA1 893ffdc, ARENA2 920e9fe fix)
**Non-teknik (herkes için):** Bir şirkette hisselerin 'iki yıl hiç dokunamazsın, sonra yavaş yavaş açılır' yazısı gibi: Budlum'un kurucu ekibinin payları bir uçurum tarihine kadar kilitli, sonrasında da yavaşça serbest kalıyor. Bu düzen, ekibin ilk gün para basıp kaybolmasını engeller; topluluk 'onlar da aynı gemide' hisseder ve uzun vadeli bağlılık görünür hale gelir. Kilit ve takvim olmasa — ya da tam tersine kilit sonsuza kadar uzasa — iki uç da kötüdür: birincisinde 'kurucular sattı gitti' diye panik başlar, ikincisinde insanlar neden çalıştıklarını sorgular; ikisi de en kritik varlık olan uzun vadeli bağlılık hissini öldürür.
- A) Linear from start + cliff'te birikmiş açılma kalsın (mevcut)
- B) Cliff'te 0 açılsın, sonra linear
- C) Vesting tamamen kaldırılsın

## Q49 — Phase 2: Prometheus + RPC rate limiting + snapshot V2 roundtrip (Phase 8.9 → 2.5/2.6)
**Teknik:** `test_metrics_initialization_and_encoding`, `test_per_ip_rate_limiting`, `test_snapshot_v2_migration_roundtrip_with_tokenomics_burn` eklendi (ARENA1 5548c42)
**Non-teknik (herkes için):** Bir arabaya hem hız göstergesi hem emniyet kemeri hem de 'eski lastikler hâlâ uyuyor mu' kontrolü konması gibi: Budlum aynı dönemde hem kendi hız göstergesini taktı, hem dış kapıdan gelen yoğun isteği yavaşlatacak sigortayı, hem de eski yedeklerin yeni yapıya oturup oturmadığını test etti. Bu üçlü sayesinde hız yalnızca hissedilmiyor, aynı zamanda kanıtlanıyor; aşırı yüke mekanik sınır var; ve geçişte 'eski arkadaşım da bu trene bindi mi' sorusu cevabını buluyor. Herhangi biri eksik kalsa: gösterge olmasa yavaşlamayı kimse görmez, sigorta olmasa ilk yoğunlukta kapı kitlenir, geriye dönük uyum testi olmasa da bir sabah biri 'benim yedeğim açılmıyor' diye bağırmaya başlar — üçü de topluluk önünde aynı gün patlayacak kadar hassas konulardır.
- A) Bu 3 test kalsın
- B) Sadece metrics ve rate limit kalsın, snapshot kaldırılsın
- C) Hepsi kaldırılsın

## Q50 — Phase 8.9 / Q5: Dummy bootnode fail-closed guard ve DNS seeds
**Teknik:** `MAINNET_BOOTNODES = ["/ip4/203.0.113.10/...", ...]` RFC5737 TEST-NET-3, `MAINNET_DNS_SEEDS = ["_dnsaddr.placeholder-seed-1.mainnet.budlum.network", ...]`, `PLACEHOLDER_PEER_MARKERS=["dummy","placeholder","203.0.113.",".example"]`, `first_placeholder_peer()` marker arar, mainnet'te DIAL edilmez CRITICAL exit 1. Test `test_placeholder_peer_detection_blocks_dummy_mainnet_entries` + F7 güçlendirme derlenmiş sabitlerin placeholder yakalanması. (893ffdc, F7 fix)
**Non-teknik (herkes için):** Bilmediğiniz bir şehirde sahte bir tabelaya bakıp sahil yoluna çıkmamak için navigasyonu kontrol etmek gibi: Budlum, içinden gelen adres listesi gerçek değilse, yani hâlâ örnek adreslerle hazırlanmışsa, kendini 'gerçek ağ modunda' başlatmayı reddediyor. Bu bekçi sayesinde 'henüz hazır değiliz' durumu asla 'hazırız sanılan' duruma karışmaz; herkes neyin eksik olduğunu açıkça görür. Bekçi kaldırılırsa bir gün sahte başlangıç noktalarıyla çalışan bir ağ, yanlışlıkla gerçek zannedilir; kullanıcılar gerçek parayı yanlış adrese gönderir ve o andan itibaren 'bu para nereye gitti' sorusunun tek cevabı kalır: hiçbir yere.
- A) Fail-closed guard kalsın, placeholder'lar törene kadar bloklasın
- B) Guard uyarı versin ama mainnet açılsın (fail-open)
- C) Guard kaldırılsın

## Q51 — Phase 8: forbid(unsafe_code) (G1 ADIM8 3.3)
**Teknik:** `src/lib.rs:1` `#![forbid(unsafe_code)]` + `#![allow(warnings)]` (user-decided, dead_code gizler). First-party 0 unsafe temiz taban, ikinci kanıt katmanı `cargo geiger` job. (PHASE8.9_ANALIZ_A1 F10)
**Non-teknik (herkes için):** İnşaat şantiyesinde 'baretsiz girilmez' yazısını binanın ta kendisine işlemek gibi: Budlum'un kodunda, bilinçli olarak tehlikeli sayılan dil özellikleri bütün projede yasaklandı. Bu yasak sayesinde ileride bir geliştirici 'sadece bir kerelik' diyerek riskli bir yola sapamaz; yasak kişilere değil binanın kendisine yazılmıştır ve kapı her zaman aynı sertlikte durur. Yasak kalkarsa ilk yıllar her şey sakin görünebilir; ama en beklenmedik bir gecede, iyi niyetli ama bilgisiz bir katkı, kapıyı ardına kadar açacak bir hata üretir — o hatanın faturası ise ancak müşteri kaybı yaşandıktan sonra görülebilir.
- A) forbid(unsafe_code) kalsın
- B) allow(unsafe_code) olsun, performans için
- C) Hiçbir şey olmasın

## Q52 — Phase 8 / G2: pedantic+nursery ratchet baseline 191
**Teknik:** `cargo clippy --all-targets -W clippy::pedantic -W clippy::nursery` → 191 uyarı/20 lint (uninlined_format_args 106, cast_precision_loss 14, cast_sign_loss 10), baseline `.github/clippy-extra-baseline.txt=191`, ARTARSA CI fail, düşürme bilinçli PR'la. (STATUS_ONLINE 263)
**Non-teknik (herkes için):** Spor salonundaki temizlik puanı panosu gibi: Budlum'da kod titizliği ölçülüyor ve bu puanın mevcut 191 seviyesinin altına düşmesi yasak. Sabit puan sayesinde 'bu seferlik görmezden gelelim' alışkanlığı ölür; verimlilik asla kalite pazarında pazarlık edilemez hale gelir ve altı ay sonra kod yine ilk günkü kadar derli topludur. Puan serbest olsaydı ilk hafta 190'a düşülür ve bir sonraki hafta 185 kalitesi 'fiili standart' sayılırdı; yavaş yavaş — kimse fark etmeden — proje eski dağınık haline döner ve gerçek ağın açılışı öncesi son denetimde 'bu nasıl olmuş' sorusu herkesin yüzüne bakar cevap bulamaz.
- A) Ratchet 191 kalsın, artarsa fail
- B) Baseline 0 olsun, tüm pedantic temizlensin
- C) Pedantic/nursery tamamen kapatılsın

## Q53 — Phase 8 / G3: udeps unused dependency kapısı (Dalga 14)
**Teknik:** `cargo-udeps --locked`, `scripts/check-udeps.sh` gerçek format parse ("unused dependencies:" + ağaç parse → paket:dep), kanaryalı self-test, baseline `.github/udeps-baseline.txt` 4 bulgu (budlum-core:chrono, group, bud-node:serde_json, bud-proof:p3-uni-stark) sıfır hit grep kanıtlı, ratchet yeni satır → fail. (dbc99b0 ARENA2)
**Non-teknik (herkes için):** Bir kütüphanede okunmayan kitapların raflardan indirilmesi gibi: Budlum'un ihtiyaç duyduğu hazır parçaların içinde gerçekten kullanılan olmayan kalmışsa otomatik denetçi kızar. Bu kural sayesinde sistem gereksiz ağırlık taşımaz; her ek paketin bir işlevi vardır ve bir gün o pakette açık çıkarsa 'biz bunu zaten kullanmıyormuşuz' ilüzyonu yaşanmaz. Ölü parçalar sürüklenirse hem saldırı yüzeyi sessizce büyür hem de bir gün kriz anında 'bu kütüphaneyi kullanıyor muyduk' sorusu cevapsız kalır; ve o sorunun cevabını aramak, gerçek yangını söndürmekten uzun sürer.
- A) Udeps ratchet kalsın
- B) Udeps tamamen kaldırılsın
- C) Udeps sadece bilgi versin, gate olmasın

## Q54 — Phase 8.5 / G11: geiger unsafe görünürlük
**Teknik:** `scripts/check-geiger.sh` kanaryalı (first-party unsafe FAIL / deps bilgi / temiz PASS) + geiger job supply-chain-extra'da, G1 forbid(unsafe_code)'dan bağımsız ikinci kanıt katmanı, third-party unsafe rapora düşer. (STATUS_ONLINE 440)
**Non-teknik (herkes için):** Bir ürün etiketinin 'içindekiler' kısmını şeffaf yazdırmak gibi: Budlum kendi kodunda tehlikeli özellik kullanmasa bile, güvendiği hazır parçalarda varsa bunu görünür raporla takip ediyor. Bu şeffaflık sayesinde 'bizim evimiz tertemiz ama temizlikçinin getirdiği şeyler ne âlemde' sorusunun cevabı vardır; sessiz bağımlılık riskleri listeye yazılıdır. Bu izleme olmasa bir gün ünlü bir krizi televizyondan öğreniriz; ardından 'bizde de var mıymış' paniği başlar ve güvenle söylenemeyen tek cümle — 'emin değiliz' — kullanıcıya asla söylenmemesi gereken tek cümledir.
- A) Geiger first-party 0 kanıt kalsın
- B) Geiger tamamen kaldırılsın
- C) Third-party unsafe de FAIL olsun

## Q55 — Phase 8.5 / G14: bud-e2e-invariants isim-kilitli job
**Teknik:** `bud-e2e-invariants` job 9 invariant + 3 e2e, `scripts/check-bud-e2e.sh` isim kanaryasıyla ZORUNLU, vacuous-gate koruması invariant silinir/yeniden adlandırılırsa cargo test yeşil kalsa bile FAIL. (STATUS_ONLINE 351)
**Non-teknik (herkes için):** Mezarlık nöbetçisinin 'bu dokuz mezar taşı silinirse hemen haber ver' diye isim isim listeli beklemesi gibi: Budlum'un en hayati dokuz olmazsa olmaz testi, isimleri değişse bile — yani biri sessizce kaybolsa bile — otomatik kapıda yakalanıyor. Bu isim kilidi o özel testleri sıradan test kazasından ayırır; biri yanlışlıkla taşınırsa ya da yeniden adlandırılırsa sistem susmadan alarm verir. İsmi kilitli olmasaydı bir gün kritik bir teminat sessizce kaybolur ve kimse fark etmez — kontrol paneli hâlâ yeşildir, çünkü 'toplam sayı tutuyor'; ama sayı tutmak ile doğru şeylerin var olması aynı şey değildir ve fark, ancak gerçek felakette öğrenilir.
- A) İsim kanaryası kalsın
- B) İsim kanaryası kaldırılsın, sadece test sayısına bak
- C) E2E job tamamen kaldırılsın

## Q56 — Phase 8 / G7: CODEOWNERS kritik yollar
**Teknik:** `/src/consensus/`, `/src/crypto/`, `/src/rpc/`, `/config/` → @lubosruler @eurymedee, org team kurulana kadar catch-all aynı ikili. (STATUS_ONLINE 353)
**Non-teknik (herkes için):** Bir banka kasasının anahtarını birden fazla müdürün tutması gibi: Budlum'un en kritik kod bölgeleri için her değişiklikte, o bölgenin sorumlusu otomatik olarak onaylayıcı diye çağrılır. Bu kural sayesinde hiçbir kritik karar, bir kişinin gece yarısı atacağı tek adımla yürümez; 'kim bakmalı' sorusu her zaman cevaplıdır. Sorumluluk listesi olmasa daha hızlı ilerlenir gibi görünür; ancak kritik dosyada bir gün yapılan hatalı değişiklik, 'kimse bakmadı mı' sorusuyla karşılaşır — ve bu soru, hatanın kendisinden daha çok yara açar.
- A) CODEOWNERS kalsın
- B) CODEOWNERS kaldırılsın, herkes her yere dokunabilsin
- C) Daha geniş team ekle

## Q57 — Phase 8 / G6: trivy image (docker-smoke.yml)
**Teknik:** `trivy image` budlum-core:smoke-test (vuln+secret+misconfig, CRITICAL/HIGH=fail+ignore-unfixed), `docker image inspect` imza kanıtı. (STATUS_ONLINE 361)
**Non-teknik (herkes için):** Bir konteyner limanında gelen kargo kutularının gümrükte taranması gibi: Budlum'un dağıtım paketi de güvenlik tarayıcısından geçmeden 'hazır' sayılmıyor. Bu tarama sayesinde kutunun içinde sinsi bir boşluk, eski bir açık ya da unutulmuş bir dosya varsa daha piyasaya çıkmadan görülür. Tarama durursa bir gün böyle bir kutudan sızan şey, o ana kadar güvenle kurulmuş sistemlerin içine taşınır; ve sonra gelen 'bunu neden görmediniz' sorusunun cevabı çok basittir: taramayı o gün atlattığımız için.
- A) Trivy image kalsın
- B) Trivy sadece bilgi versin, fail olmasın
- C) Trivy kaldırılsın

## Q58 — Phase 8.5 / G27: zizmor workflow güvenlik lint'i + G5 persist-credentials sertleştirme
**Teknik:** zizmor v1.27.0 sürüm+sha256 pinli, `scripts/check-zizmor.sh` kanaryalı (pull_request_target+head-checkout→FAIL, temiz→PASS), repo-lint job'ında kapı, 0-bulgu politikası, `persist-credentials: false` sertleştirme. (STATUS_ONLINE 363-365)
**Non-teknik (herkes için):** Bir apartmanın yönetim kurulunın kendi toplantı tutanaklarını dahili denetime vermesi gibi: Budlum'da otomasyon akışları da — robotların kimin neyi girebileceği, kimi parolasız görebileceği — sürekli bir güvenlik denetçisinden geçiyor. Bu katman sayesinde otomasyon sistemi kendisi saldırı kapısı olmaktan çıkar; 'kim bu işi başlattı' sorusunun cevabı her zaman izli bir dosyada durur. İnceleme olmasa bir gün bir ayar dosyasında yapılan 'zararsız görünen' değişiklik, sessizce kimsenin izlemeden her şeye erişim kapısını açar; böyle bir kapı mekanik olduğu için dışarıdan saldırgandan daha tehlikelidir — çünkü hiç şüphe uyandırmadan uzun süre açık bekler.
- A) Zizmor 0-bulgu kalsın
- B) Zizmor uyarı versin ama geçsin
- C) Zizmor kaldırılsın

## Q59 — Phase 8.4 / G4: modul-bazlı coverage altyapısı (ratchet 64.00→60.00)
**Teknik:** `cargo llvm-cov` `coverage/cov.json`, `scripts/check-coverage.sh` kanaryalı, baseline `.github/coverage-baseline` (64.00 → 60.00), düşerse fail, `coverage/` artifact 30 gün. (Phase 8.4 Dalga 12, Phase 8.9 Dalga 7b)
**Non-teknik (herkes için):** Bir öğrencinin her dönem aldığı karne notunun birikim listesi gibi: Budlum her kod bölümünün ne kadarının testle döşeli olduğunu ölçüyor ve bu oran bir kez %60'a çekildikten sonra asla aşağı düşmemesi gereken bir çıta oluyor. Çıta sayesinde kimse 'bu sefer testi atla' diyemez; her yeni iş kendi güvencesiyle gelir ve genel güvenlik ağı kalınlaşır. Çıta kalkarsa 'sadece bu modülü sonraya bırakalım' diye başlayan istisnalar birikir ve bir yıl sonra her şey görünürde sağlam ama kritik birkaç bölge çoraktı — tam da kriz an ilk o çorak bölgede patlar, ve ölçümün olmadığı ayların bedeli o gecede ödenir.
- A) Coverage ratchet kalsın (60.00)
- B) Coverage sadece bilgi, gate olmasın
- C) Coverage kaldırılsın

## Q60 — Phase 8.10/8.11: actionlint + buf + genesis schema + branch protection (Repo Lint)
**Teknik:** `actionlint` workflow lint, `buf build+lint+breaking` (`.git#branch=origin/main` fix F8), `check_genesis_schema.py` mainnet/testnet/devnet JSON schema `base_fee + bud_tokenomics` var mı, zizmor. (510a510, 4c46f64)
**Non-teknik (herkes için):** Bir resmi kurumda gelen evrakların hem düzenlenişinin hem imzalarının hem de dosyaya işlenişinin ayrı ayrı kontrol edilmesi gibi: Budlum'da da otomasyon dosyaları, uzmanlık tarifleri, başlangıç belgeleri ve dal koruma kuralları hepsi tek tek denetleniyor. Bu parçalı kontrol, küçük ama birbirine zincirli hataların — biçim yanlış, isim yanlış, kural yanlış — kapıdan geçememesini sağlar. Kontrolü tek kapıda toplasaydık bir türdeki hata gözden kaçardı; ve kaçışın fiyatı her zaman aynıdır: bir sabah 'nasıl olmuş da görülmemiş' sorusu ve topluluk önünde okunamayan sessizlik.
- A) Repo Lint tam kalsın
- B) Sadece actionlint kalsın
- C) Repo Lint kaldırılsın

## Q61 — Phase 9 F2: MainnetActivation wire vs kaldır vs config-driven (Q-X2)
**Teknik:** `bud-isa::MainnetActivation {verify_merkle_enabled:bool}` + `decode_for_mainnet()` + `MainnetActivationRequired` error, VM `decode_instruction(raw, mainnet_mode)` içinde `is_verify_merkle_enabled()` env var `BUDLUM_VERIFY_MERKLE` (config `features.verify_merkle` true default) → `full()` (gate open) vs `default()` (closed). ARENA3 bayrak kaldır önerisi, ARENA2 wire, son karar config-driven (6dd66e5). (F2 fix)
**Non-teknik (herkes için):** Bir sitenin kapısına takılacak güvenlik camlarının kalınlığına karar verip, bu kalınlığı apartman yönetim defterine kalıcı yazmak gibi: Budlum'un en hassas doğrulama özelliğinin gerçek ağda devreye ne zaman gireceği ayarlardan okunuyor ve bu ayar törenle değiştirilebilir. Bu esneklik, keşif aşamasında sistemi hızlı tutarken açılış günü aynı pencereden 'şimdi geç' diyebilmeyi sağlar. Karar koda gömülü olsaydı her durum değişikliği kod değişikliği gerektirirdi; ve açılış günü hiç uygun olmayan bir hata — 'hazır değildi ama kapıdaydı' — büyük günü gölgeleyebilirdi.
- A) Config-driven kalsın (features.verify_merkle + env var, default true=open)
- B) Bayrak tamamen kaldırılsın, her zaman açık (dürüst doc)
- C) Bayrak hep kapalı kalsın, sadece testnet'te açık
- D) Config-driven ama default false (staged rollout, ceremony'de true yapılır)

## Q62 — Phase 9 F2: Genesis ceremony'de verify_merkle flip (Q-X2 devamı)
**Teknik:** `MAINNET_GENESIS_CEREMONY.md` §6 bootnodes + DNS seeds placeholder, şimdi `verify_merkle` flip de ceremony checklist'e eklenmeli mi? `GENESIS_FLIP_CHECKLIST.md` cross-ref.
**Non-teknik (herkes için):** Bir düğünün akşamında 'amcamın yüzüğü getirmesini unutmayın' diye listeye not düşmek gibi: Budlum'un açılış töreni kontrol listesine, bu çok kritik özelliğin o gün gerçekten açılıp açılmadığının işaretlenmesi eklendi. Böylece törenin koşuşturmacasında, onlarca madde arasında bu önemli düğme unutulmaz; açılış günü sabahı ekipten biri listeye bakar ve 'düğmeye basıldı, işte burada işaretli' der. Liste maddesi olmasa o büyük gün, herkes birbirine baktığında durumun cevabı sadece varsayımla konuşulur; ve yıllar sonra 'o özellik ilk günden mi vardı, sonra mı geldi' sorusuna arşivlerden kesin cevap verilemez.
- A) Evet, ceremony checklist'e verify_merkle flip ekle
- B) Hayır, sadece config yeterli
- C) Ceremony dokümanı tamamen kaldır

## Q63 — Phase 9 F3: Vendor mechanism wiring (Q-X3)
**Teknik:** `Pkcs11Signer::with_vendor_mechanisms(Option<String>, Option<String>)` parse `"0x..."` hex veya decimal, `MechanismType::new_vendor_defined` fail-closed, `VendorDefinedMechanism::new::<()>(mech_type, None)`, `try_vendor_sign` BLS/PQ için. (V14 fix)
**Non-teknik (herkes için):** Bir bankanın 'özel üretilmiş güvenlik kartı'nı alıp okuyucuya tanıtmak için, o bankaya özel okuma kılavuzunu resmi dosyaya işletmesi gibi: Budlum'un donanım kasasının kendi üreticisine özel imza yöntemi, artık sistemin resmi ayar bütününde tanımlı. Bu kayıt sayesinde özel üretim kasaya güvenen operatör, yarın o korumayı gerçekten devreye alabilir; söz verilen donanım güvenlik seviyesi fiilen yaşanır hale geliyor. Kayıt yapılmasaydı özel kutu rafta kalır, sistemin yeni güvenlik faydası lafta kalırdı; ve bir sonraki denetimde 'bu üreticinin özel mekanizmasından yararlanıyor musunuz' sorusuna verilecek tek cevap, utançla 'kağıtta var ama uygulamada yok' olurdu.
- A) Vendor mechanism wire kalsın (mevcut)
- B) Wire kaldırılsın, sadece software fallback
- C) Vendor mechanism tamamen kaldırılsın, sadece Ed25519 HSM

## Q64 — Phase 9 F4: Boost weighted distribution (Q-X4 devamı)
**Teknik:** `pending_bud_boost_share` biriktir, `distribute_bud_boost_share(boost_share)` aktif deal'lerin `fee_per_epoch` ağırlığına göre dağıt, `share = boost_share * weight / total_weight`, dust ilk deal operatörüne, aktif deal yoksa burn. `add_balance`. Test `boost_share_distributes_by_deal_fee_weight_with_dust_to_first` ve `boost_without_active_deals_burns_share_and_drains_pool` mühür. (7f054d7, eb45388, aa9cfcd fix op1/op2 51/52)
**Non-teknik (herkes için):** Bir lojistik şirketinde bahşişin, en çok yol yapan sürücüye en çok gidecek şekilde dağıtılması gibi: Budlum'da öne çıkarma ücretlerinden depoculara düşen pay, herkesin o dönem ne kadar süre gerçekten çalıştığına oranla paylaştırılıyor; kalan kırıntılar da sistemli şekilde ilk sıradakine veriliyor. Bu yöntem hem adil hem de sızdırmazdır: ne bir fazla dağıtılır ne bir eksik kaybolur; kuruşun kuruşuna hesabı kapalıdır. Düz dağıtımda az çalışan çok çalışanıyla aynı parayı alır ve bu his, zamanla sistemin en ciddi çalışanlarını bezdirebilir; bölünmemiş kalıntı birikirse bir yıl sonra 'nerede bu artanlar' sorusuna kimse cevap üretemez ve muhasebe anlaşmazlığı, iyi işleyen bir sistemin moral örseleyicisi olur.
- A) Weighted + dust first kalsın (mevcut)
- B) Eşit dağıtım (her operatöre aynı)
- C) Stake ağırlıklı dağıtım (ne kadar stake o kadar pay)
- D) Tamamı ilk operatöre

## Q65 — Phase 9 F5: Genesis persistence `let _ =` → `tracing::error!` (High bulgu)
**Teknik:** `blockchain.rs:503-504` `insert_block` + `save_last_hash` dead_code path + `:2843` reorg sonrası `save_last_hash` ve `load_state` artık `if let Err(e) => tracing::error!`. 267 total `let _ =` içinde kritik yollar sertleştirildi, Option/rx.await bilinçli dokunulmadı. (ARENA3 7/16 High, F5 fix)
**Non-teknik (herkes için):** Bir kargo firmasının 'kutuyu teslim edemedik ama söylemedik' türünden hataları gizlememesi, çıkıp müşteriye haber vermesi gibi: Budlum'un kodunda, kalıcı kayda yazma işlemi başarısız olursa artık bu sessizce yutulmuyor, gürültülü bir alarm kaydı düşülüyor. Bu bağırtı sayesinde 'sessizce kaybolan bir kayıt' imkânsızlaşır; aksayan şey, ilk saniyede kayıt defterine işaret düşer ve operatörün gözü önündedir. Sessiz yutma geri gelseydi bir gün kritik bir kayıt 'yazıldı sanılıp' aslında hiç yazılmazdı; ertesi gün o kayda güvenilip atılan bir adım boşluğa basardı ve suçlu arandığında elde ne kayıt kalırdı ne de şüpheli izi — sadece 'bir şeyler ters gitti galiba' duygusu.
- A) Error log ile görünür kalsın (mevcut)
- B) Sessiz yutma geri gelsin (`let _ =`)
- C) Panic olsun (fail-fast)

## Q66 — Phase 9 F6: Test-count prose stale (badge vs README)
**Teknik:** Badge `tests-538/539/546%20lib` otomatik bot (`chore(badge): tests rozeti -> N lib (CI kanitli, SHA)`), prose `README.md:114` ve `MAINNET_READINESS.md` manuel tazeleme, bot loop guard'lı self-commit. (F6 fix)
**Non-teknik (herkes için):** Gazetedeki 'bugün itibarıyla stokta X adet' ifadesinin manuel değiştirilmesi gibi: giriş sayfasındaki rakam (rozet) otomatik güncellenirken, metin içindeki aynı rakam insan eliyle tazeleniyor. Bu ikili düzen sayesinde mekanik kusur otomatik yakalanır ama cümle içindeki anlam da insan gözünden geçer; iki taraf birbirini denetler. İki yöntemin de ihmal edildiği bir dünyada rakam sürüklenir ve bir sabah biri 'bu sayfa aylardır geriden yazıyor' diye ekran görüntüsü paylaşır; sonrasında sayfadaki her rakam kuşkulanmaya başlar — bu da güvenle ilan edilen her başarının da sorgulanması demektir.
- A) Badge otomatik, prose manuel (mevcut)
- B) Prose da otomatik olsun
- C) Sadece badge yeterli, prose kaldırılsın

## Q67 — Phase 9 F7: Guard test strength regression (F7)
**Teknik:** `test_placeholder_peer_detection_blocks_dummy_mainnet_entries` synthetic dummy + compiled `MAINNET_BOOTNODES` ve `MAINNET_DNS_SEEDS` placeholder yakalama assert'i (derlenmiş sabitler). (F7 fix, c953049 regresyonu)
**Non-teknik (herkes için):** Bir kapıdaki güvenlik görevlisinin, elindeki listede yazan sahte isimler dışında, duvarda kazılı sahte isimleri de tanıması gibi: Budlum'un 'önümüzdeki gerçek adres sahte olmasın' testi, artık listeye eklenmiş örnekleri değil, kodun içine işlenmiş gerçek sahte işaretleri bile yakalıyor. Bu iki kollu kontrol sayesinde sahtelik ne liste dışı örnekle ne de derlemenin içindeki gizli kopyayla süzülemez; kapı her iki taraftan da mühürlüdür. Tek kollu test olsaydı bir gün compilasyonun derin köşesine gömülmüş bir 'örnek adres' kimsenin dikkatini çekmeden canlı ağda bulunurdu ve onu fark eden dış göz, 'demek ki kontroller yalnızca yüzeysel' sonucuna kolayca ulaşırdı.
- A) Güçlendirilmiş test kalsın (synthetic + compiled)
- B) Sadece synthetic yeterli
- C) Test tamamen kaldırılsın

## Q68 — Phase 9 F8: CI buf breaking step non-main dallarda kırık
**Teknik:** `ci.yml:442` `buf breaking --against '.git#branch=main'` → `'.git#branch=origin/main'` (local main ref yokken repo lint kırmızı, job 87812434426 kanıtı). Token `workflows` izni yok, ARENA2 fix. (F8)
**Non-teknik (herkes için):** Bir mağazanın merkeziyle şubesi arasında bağlantı kopunca şubedeki 'merkezi onay' zorunluluğunun işlemleri kilitlediği gibi: Budlum'da da yan dalda çalışırken ana dalın referansı kaybolunca denetim haksız yere kızıyordu — bu düzeltildi. Bu düzeltme sayesinde hiçbir çalışan, ana merkezle anlık bağ kopunca 'her şey durdu' paniği yaşamaz; yan işler kendi ekseninde denetlenir, birleşince yekûn görünür. Eski davranış kalsaydı, her yeni dalın ilk hamlesinde yaşanan anlamsız kırmızı, ekibe 'sistem şımarık' hissini öğretirdi; gerçek kırmızı geldiğinde de kimse durdurmaz — 'nasılsa yine şımarıyor' denecek kadar yorgun bir ekip, en ciddi alarmı da kaybeder.
- A) origin/main fix kalsın
- B) main kalsın (eski, dallarda kırmızı)
- C) Buf breaking tamamen kaldırılsın

## Q69 — Phase 9 F9: Genesis hash constant unasserted + drift
**Teknik:** `config/mainnet.toml:5` hash `02166d370613fc70e5beb47e4d1ef48e5ccad93eb0f4b8bd5edfe5787a7f98fc` (eski `9bf07f9f...` drifted), `test_mainnet_genesis_hash_matches_documented_constant` absolute assert, `PRODUCTION_RUNBOOK.md` §8.2 ve `mainnet.toml` comment sync. (F9 fix 5fb7215, 4aa616f)
**Non-teknik (herkes için):** Bir antika masanın altındaki 'şu atölyede, şu yılda yapılmıştır' damgasının masa hakkındaki kitaba aynen yazılması ve her ikisinin birbirine eşliğinin test edilmesi gibi: Budlum'un ilk günkü kimlik işaretinin, dokümandaki resmi ifadeyle birebir aynı olduğu her derlemede kanıtlanıyor. Bu test sayesinde zaman içinde ufak düzeltmeler birikip kimlik sürüklenmez; ilk günkü sözleşme neyse yıllar sonra da odur, iki tarafı her an yan yana koyup karşılaştırabilirsiniz. Bu eşitlik testi olmasa bir gün doküman ile kod arasında sessiz sapma oluşur; ve yıllar sonra bir arşiv araştırmacısı 'hangisi doğruydu' diye sorduğunda, iki kaynağın da 'ben doğruyum' dediği patolojik durumla karşılaşılır — o noktadan sonra da hiçbir tarihsel karar kolay alınamaz.
- A) Absolute assert kalsın (drift yakalar, mevcut)
- B) Sadece JSON==code eşitliği yeterli (relative)
- C) Genesis hash hiç dokümante edilmesin

## Q70 — Phase 9 F10: `#![allow(warnings)]` + `forbid(unsafe_code)`
**Teknik:** `src/lib.rs:1` `#![allow(warnings)]` user-decided, dead_code görünürlüğünü kapatır, denetim manuel grep ile, `#![forbid(unsafe_code)]` bağımsız. (F10 note, ⚪)
**Non-teknik (herkes için):** Bir atölyede 'tozlu alarm susturulsun ama kimyasal dolabın kilidi kalsın' yazısı gibi: kodun içinde tüm uyarı ışıkları susturulmuş durumda, ama tehlikeli sayılan teknik özelliklerin yasağı yürürlükte. Bu karar, gürültünün yerine kesin yasağı tercih ediyor; 'rahatsız edici ama zararsız' sinyaller susturuluyor, 'görmezden gelinemez' yasak korunuyor. İki karar birbirine karıştırılırsa ya her şey susturulur — o zaman kritik kilit de açılır ve güvenlik ölür; ya da her şey alarm verir — o zaman da gerçek alarm, gürültü kalabalığında boğulur ve bir sabah dikkatsiz bir göz, ciddi sinyali 'her zamanki şamata' sanıp geçer.
- A) allow(warnings) + forbid(unsafe_code) kalsın (mevcut)
- B) allow(warnings) kaldırılsın, tüm uyarılar gösterilsin
- C) forbid(unsafe_code) kaldırılsın

## Q71 — Phase 0.378 Gap Matrix ve Execution Plan
**Teknik:** `PHASE0.378_GAP_MATRIX.md` ve `EXECUTION_PLAN.md` BLS/PQ key protection, finality live-path, ConsensusStateV2 notları, external audit checklist, README roadmap, DEVIR raporu. (Phase 0.378)
**Non-teknik (herkes için):** Büyük bir taşınmadan önce her odanın fotoğrafını çekip 'bu gidecek, bu kalacak, bu tamir edilecek' diye liste tutmak gibi: gerçek ağa geçmeden önce Budlum'un tüm borçları tek bir deftere dökülmüş durumda. Bu defter sayesinde 'acaba neyi unuttuk' endişesi, kontrol edilebilir bir listeye dönüşür; her borç bir satırdır ve kapanan her satır görünür ilerlemedir. Liste olmasa borçlar insanların kafasında yaşar; bir kişi ayrıldığında o borç da onunla gider ve bir gün kritik bir eksik, en uygunsuz anda — örneğin açılış haftası — 'bunu kimse yapmadı mı' sorusuyla ortaya çıkar. O sorunun cevabı her zaman aynıdır ve hep geç kalınmıştır.
- A) Gap matrix güncel tutulup kapatılsın
- B) Gap matrix kaldırılsın
- C) Gap matrix sadece dış denetçiye verilsin

## Q72 — Phase 0.42: Mainnet Launch (2 alt-tur: 0.43 devnet pilot + harici audit, 0.438 audit kabul + launch)
**Teknik:** Phase 0.40 önkoşul 7 iş paketi (BLS/PQ HSM, B.U.D. Faz 1-2, finality live-path, ConsensusStateV2, external audit checklist, README roadmap, fuzzing/audit/SBOM). Phase 0.43: storage-operator.toml, 3+ bağımsız operatör, E2E smoke, permissionless kayıt testi, 1 hafta monitoring + audit firması seçimi/kickoff. Phase 0.438: AUDIT_REPORT, mainnet.toml Config V2 strict, governance/budzkvm_contract/pruning=false, ORG_ROADMAP_AUDIT §4b. (PHASE0.42_PLAN.md)
**Non-teknik (herkes için):** Bir kebap ustasının lokanta açmadan önce yemekleri önce arkadaşlarına sunması, sonra ilçenin gıda denetçisini çağırması, ancak ondan sonra tabela asması gibi: Budlum önce küçük bir deneme sürüşü yapacak, sonra bağımsız uzman denetinden geçecek, ancak ikisi de temiz çıkarsa ana kapıyı açacak. Bu sıra, 'heyecanla erken açanı' cezalandıran, 'sabırla hazırlananı' ödüllendiren bir düzendir; hata, ucuz olduğu aşamada yakalanır. Sıra bozulup açılış öne çekilirse herhangi bir sorun, kamunun önünde ve para riski altında öğrenilir; ve o ilk izlenim kötü olursa — ilk günü kaçıran müşteri gibi — bazı kullanıcılar bir daha asla geri dönmez. Sabır burada kusur değil, en değerli yatırımdır.
- A) 2 alt-turlu plan kalsın (mevcut)
- B) Tek turda direkt mainnet
- C) Mainnet hiç yapılmasın, sonsuza kadar devnet

## Q73 — Phase 8.9 Analiz: Bitmiş/kırık/çürümüş/placeholder ayrımı
**Teknik:** Matris 3 kova: (A) kırık/çürümüş → bu süreçte düzeltilecek; (B) dokümante-placeholder kodu sağlam → ceremony gününe kadar boşluk değil; (C) kullanıcı-taraflı fiziksel kalemler (7.1 genesis keys, 7.2 bootnode gerçekleri, 7.3 HSM donanımı, M7 dış denetim) → tooling/şablon/fail-closed guard/checklist/hash-freeze kapatılacak, kalan "ceremony günü input listesi" dokümanında toplanacak. (PHASE8.9_ANALIZ_A1.md §1)
**Non-teknik (herkes için):** Bir emlakçının eve girip 'bu oda bitti, bu banyo dökülüyor, bu dolap sadece kartondan ama taşıyabilir' diye dürüst rapor tutması gibi: Budlum'da her parça 'bitmiş mi, bozuk mu, bilerek mi öyle bırakılmış' diye üç kovaya ayrıldı. Bu ayrım sayesinde bir karton dolap için aylarca tamirat yapılmaz; bozuk olana da hemen usta çağrılır; ve en önemlisi, tören günü gerçekten dışarıdan gelecek şeyler (fiziksel anahtarlar, gerçek adresler) ile şimdi bitirilebilecek işler karışmaz. Ayrım yapılmadan çalışmak, zamansızlığın kendisidir: bir gün 'bu zaten bitmişti' denen işin bozuk olduğu ortaya çıkar, bir başka gün kasten yer tutucu bırakılan şeye 'kırık iş' etiketi yapıştırılır ve ekip enerjisi yanlış yerlere akar.
- A) 3 kova ayrımı kalsın
- B) Her şey şimdi bitirilsin (ceremony yok)
- C) Her şey ceremony'ye ertelensin

## Q74 — Phase 1 Rapor: B.U.D. Faz 1-2 + Faz 5 iskeleti PR #6
**Teknik:** PR #6 HEAD `39e30c7` 8 commit: ARENA_AI.md adaptasyon, STATUS.md, 4 kayıp PR kurtarma, finality_live_path revert, Phase 0.38 Rust iskeleti `ConsensusKind::StorageAttestation(StorageDomainParams)` + `STORAGE_OPERATOR=RoleId(5)` + `ContentId`+`of_subrange` + `ContentManifest`+`ShardRef`+`manifest_id_from_shards` + `StorageDeal`+`StorageRegistry`+`RetrievalChallenge/Response/Outcome/Result` + 7 storage RPC + 3-aktör E2E + 9 ekip-bağımsızlık invariant. (PHASE1_RAPOR.md, STATUS.md)
**Non-teknik (herkes için):** Bir kooperatifin ilk şubesinin kapılarını açması gibi: dosya emanet etme işinin temel binası dikildi; kayıt defteri, görevlendirmeler ve güvenlik kuralları yerinde; ilk müşteriler içeri alınıp sistem gerçek insanlarla sınandı. Bu kapı, 'bir gün yapacağız' sözünün 'yapıldı' kanıtına dönüştüğü andır; topluluk artık boş vaat değil, çalışan bir şey görüyor. Bu temel gecikseydi ya da çürük çıksaydı, üzerine inşa edilecek her kat — mobilya, tabela, ikinci şube — riske girerdi; en kötüsü de bu aşamada çürük çıkan temelin, ilerideki bir kriz anında, kimsenin tahmin edemediği bir biçimde sallanması ve yükünün artık hesaplanamayacağı bir noktada kırılması olurdu.
- A) Phase 1 kapsamı doğru, PR #6 merge kalsın
- B) Phase 1 fazla büyük, küçültülsün
- C) Phase 1 tamamen geri alınsın

## Q75 — Phase 0.06 aslında Phase 0.44: VerifyMerkle gate (detaylı)
**Teknik:** `is_experimental()=false` tüm opcode'lar production-ready, `decode_for_mainnet` + `MainnetActivationRequired` + 3 test (default reject, full allow, other bypass), `tur119_verify_merkle_disabled_in_production` kaldır/güncelle, `GlobalBlockHeader.storage_root` block hash'e dahil. (docs/PHASE0.06_PLAN.md aslında 0.44)
**Non-teknik (herkes için):** Bir atölyede yıllardır kullanılan kritik bir makinenin 'deneysel' levhasının sökülmesi gibi: Budlum'un içindeki her temel hareket, 'tam üretim gücüyle hazır' olarak işaretlendi; hiçbir komut 'belki çalışır' sınıfına girmiyor. Bu işaretle birlikte, gerçek ağda çalıştırılabilecek ve çalıştırılamayacak iş listeleri kesin ayrılmış oldu; sınırlar biliniyor ve herkes aynı sayfada. Bu sınır belirsiz kalsaydı — bazı işler 'deneysel ama kullanılıyor' gibi yaşasaydı — ilk ciddi arızada 'bu komut zaten deneyseldi, neden güvendin' ile 'sen neden üretimde kullandın' tartışması başlar; suçlu aramaktansa suç ortadan kalkmalıydı ve bu karar tam da bunu yapıyor.
- A) VerifyMerkle gate açık kalsın (mevcut)
- B) Gate kapalı kalsın
- C) Gate sadece experimental feature ile açık

## Q76 — Phase 0.08 aslında 0.46: Universal Relayer + Mobile B.U.D. Light Node
**Teknik:** `ExternalChain` enum (Ethereum, Solana, Bitcoin), `ExternalTransaction` Budlum cüzdanı ile imzalanıp relayer dış zincire basar, RPC `bud_relayerPrepareExternalTx`, `MobileConfig` batarya/Wi-Fi dostu limitler, `ShardManager` self-host önceliği, `Node::run` NftBurn worker `store.delete(cid)`. (PHASE0.08_PLAN.md)
**Non-teknik (herkes için):** Bir bankanın hem cep telefonundan bakiye sorgulama uygulamasını hem de komşu ülke bankalarına döviz havalesini başlatması gibi: Budlum'da hem telefon bilek gücünde hizmet verebiliyor hem de dışarıdaki farklı sistemlerle köprü kurulabiliyor. Bu iki genişleme sayesinde cebindeki telefonla dosya saklayabilen herkes ağın parçası olabilir; ve başka ağlarda yaşayan varlıklar, Budlum'a taşınabilir. Bu kapılar açılmazsa Budlum güçlü ama yalnız kalır: kullanıcı kitlesi sadece 'bilgisayarı güçlü olanlar'a kısalır; ve diğer ağlarla konuşamayan her sistem, o büyük akışın dışında kalır — tarih, içe kapalı iyi sistemlerin dışa açık sıradan sistemlere yenildiğini defalarca göstermiştir.
- A) Relayer + mobile light node kalsın
- B) Sadece relayer kalsın, mobile kaldırılsın
- C) İkisi de kaldırılsın

## Q77 — Phase 0.10 aslında 0.48: B.U.D. Gateway + Relayer EVM Proofs + SocialFi Feed
**Teknik:** Gateway `.bud` ismini HTML/Media'ya çeviren proxy `bud_gatewayFetchContent`, `RelayerExternalResult` receipt proof, SocialFi feed NFT sahipliğine dayalı SQL/Index, mainnet bootnodes tören sonrası P2P, Eco-Frontend proto Hub web. (PHASE0.10_PLAN.md)
**Non-teknik (herkes için):** Bir mağazanın vitrinini, içeri giremeyenlerin bile camdan görebileceği şekilde düzenlemesi gibi: Budlum'daki bir isme, özel bir program yüklemeden de tarayıcıdan bakılabiliyor; ve dışarıdaki başka bir sistemde olan biten, oradaki makbuzuyla burada kanıtlanabiliyor. Vitrin sayesinde meraklı milyonlar 'önce şu yazılımı indir' duvarına çarpmaz; makbuzlu kanıt sayesinde ise 'orada şöyle bir işlem oldu' dediğinizde, kimseye değil belgeye güvenilir. Bu iki kapı kapalı olsa Budlum, yalnızca içeridekilerin içeridekilerle vakit geçirdiği bir kulüp olur; dış dünyaya dokunamayan bir platform büyüyemez ve ilk fırsatta otorite sınaması geldiğinde kendini kanıtlamak için kullanabileceği bağımsız belgeleri olmaz.
- A) Gateway + proofs + feed kalsın
- B) Sadece gateway kalsın
- C) Hepsi kaldırılsın

## Q78 — Phase 8.9 Dalga 1+2+3 (README 509→522, C1 dangling, .gitignore sbom, fuzz check)
**Teknik:** Dalga 1 küçük README 509→522 + L113 452→522 + C1 dangling Q1, .gitignore+sbom.cdx.json + cargo-fuzz metadata; Dalga 2 Q2+Q3 belge birleştirme/silme + genesis hash freeze checklist; Dalga 3 Q5 dummy-bootnode fail-closed guard + key-üretim script + allocations/validators JSON schema + ceremony input list tek dosya. (PHASE8.9_ANALIZ_A1.md §5)
**Non-teknik (herkes için):** Büyük temizlik başlamadan önce evdeki küçük dağınıklıkların toplanması — çözümün yarısının düzen gibi: Budlum'da önce giriş sayfasındaki sayılar doğrulandı, kullanılmayan dosyalar atıldı, sonra ayrı duran benzer belgeler birleştirildi ve son olarak kritik bir güvenlik bekçisi dikildi. Bu dalganın sayesinde ortam netleşti; denetçinin gözü dağınıklıkta değil özlü işte kaldı ve 'acaba gerçekten bu kadar mı' şüphesi, karşılanabilir bir güvene dönüştü. Düzen alınmadan büyük temizliğe kalkışmak, mobilyaların üstünden toz almaktır; toz kalkar görünür ama alttaki pislik kalır ve sonraki bahar temizliği her seferinde daha zorlaşır. Bu dalganın her maddesi bir sonrakine merdiven oluyor ve merdivenlerin eksik olanı, ileride basamak uçurum demek.
- A) Dalga planı kalsın
- B) Tüm dalgalar tek seferde yapılsın
- C) Dalga planı iptal

## Q79 — Phase 8.9 kalan ADIM 8.5 maddeleri (P1.1/P1.7/miri, geiger, semver-checks, cosign SBOM-signing, KAT vectors, dudect, PKCS#11 mock negative tests, X-Real-IP spoofing, zizmor, branch protection)
**Teknik:** ADIM8 3.3 Faz1 tamamlandıktan sonra P1/P2 ve ADIM8.5 eksikleri listesi (STATUS_ONLINE 2026-07-16 19:45 ARENA3). (PHASE8.9)
**Non-teknik (herkes için):** Bir okulun güvenlik soruşturmasından sonra 'kapılar tamam ama bahçe aydınlatması, kör nokta kameraları ve tatbikat takvimi eksik' raporu gibi: Budlum'da ana güvenlik işleri bitti ama kalan ince işler — ek denetimler, zamanlama ölçümleri, olumsuz-senaryo testleri — tek tek listelendi. Bu liste önemlidir çünkü güvenlik her zaman 'kalan son %5'in içinde saklanır; sonlandırılmamış bir liste yarım kalır ve yarım kalan bir güvenlik, tam kapanmamış bir kapıdan farksızdır. Liste unutulsaydı bir gün dışarıdan bilgi isteyen ciddi bir alıcıya — bir kurumu, bir denetçiyi — 've son olarak şunlar da vardı' diye sunulacak tatmin edici bir tablo olmaz; onlar için 'tamamlanmamış' sinyali görmek, 'tamamlanmış ama bahsedilmemiş' olandan daha tehlikelidir çünkü birincisi kültürü sorar, ikincisi sadece iş bitirmeyi.
- A) ADIM8.5 maddeleri tek tek kapatılsın
- B) Hepsi ertelensin, Phase 10'a
- C) Sadece miri ve geiger kalsın

## Q80 — MAINNET_READINESS MR-1..MR-10 (Phase 8.9 Dalga 5 sonrası)
**Teknik:** MR tablosu: Phase 8 full closure ADIM8-TALIMAT-1 (12 tasks) + ADIM8.5 add-ons (miri, geiger, semver-checks, cosign SBOM-signing, KAT vectors, dudect, PKCS#11 mock negative tests, X-Real-IP spoofing, zizmor, branch protection) + uploads talimat + CI kapıları. (MAINNET_READINESS.md MR-2)
**Non-teknik (herkes için):** Pilotun kalkıştan önce pisti, yakıtı, hava durumunu ve kabin ekibini tek tek saydığı son kontrol listesi gibi: gerçek ağa uçmadan önce Budlum'un 'tamam demek için ne gerekir' maddeleri MR-1'den MR-10'a kadar numaralandı. Bu liste her iddianın bir kapısını oluşturur; 'hazırız' demek için listenin her satırı işaretlenmeli ve o işaret, kanıtsız değil görülerek konmalı. Liste kullanılmazsa 'herkes işini bitirdi sanıyorduk' sorusu ilk ciddi sarsıntıda gelir; o sorunun sorulduğu anda ise artık geriye dönük liste tutmak imkânsızdır — çünkü liste, sıkıntılı günde değil, sakin günde tutulandır.
- A) MR listesi güncel tutulup yeşil olmadan mainnet yok
- B) MR listesi bilgi amaçlı, mainnet kararı ayrı
- C) MR listesi kaldırılsın

## Q81 — ORG_ROADMAP_AUDIT §4a 18 madde tablosu
**Teknik:** PR #6 CI yeşil, PR başlığı doğru, HEAD 39e30c7, StorageAttestation enum varyantı VAR, STORAGE_OPERATOR RoleId 5 VAR, content_id.rs, manifest.rs, storage_deal.rs, bud_e2e.rs VAR, docs/BUD/ kısmen, permissionless PoA izolasyon testi VAR, budlum.com URL YOK, admin/pause/freeze/owner hook YOK, B.U.D. upstream vizyon 495 satır VAR, 7 storage RPC VAR, PoA izolasyon bozulmadı. (ORG_ROADMAP_AUDIT.md §4a)
**Non-teknik (herkes için):** Bir şirketin yıllık hedef tablosunu yıl sonunda maddeler halinde 'yapıldı/yapılmadı' diye damgalaması gibi: organizasyonun kendine koyduğu yol haritasının on sekiz maddesi tek tek karşılandı ve her biri kanıtla işaretlendi. Bu damgalama dürüstlüğün meyvesidir: kimse kendi tablosunda 'yapıldı' yazmaya cesaret edemez ve yıllar sonra arşiv açıldığında 'o gün nereye kadar gelmiştik' sorusunun kesin cevabı vardır. Tablosuz yolculuk eninde sonunda kişisel hislere döner: biri 'biz bunları yapmıştık' der, başkası 'hatırlamıyorum'; ve bir karar gerektiğinde, ortak tarihsizlik herkesi farklı gerçekliklerde yaşar hale getirir. Ortak tablo, ortak geçmiş demektir.
- A) 18 madde audit tablosu kalsın ve güncel tutulsun
- B) Audit tablosu kaldırılsın
- C) Audit tablosu sadece dış denetçiye verilsin

## Q82 — B.U.D. data-sovereignty kuralı (Phase 0.39 plan §0.5)
**Teknik:** `open_deal` ve `open_challenge` permissionless, opener_bond >0 anti-spam, admin/pause/freeze/force hook kodu incelemesiyle YOK (`grep -n 'fn admin_\|fn pause_\|fn force_\|fn owner_\|fn freeze_'` boş). (PHASE0.42_PLAN.md §4.7)
**Non-teknik (herkes için):** Mahkemeye gitmeden de tapu işlemi yapabilme hakkı gibi: Budlum'da bir depolama anlaşması açmak için kimsenin özel iznine, başvurusuna, ya da bekleme sırasına ihtiyaç yok; ve bu özgürlüğü kısıtlayacak gizli 'durdurma düğmesi' kodda bulunmuyor. Bu kural, hayati bir vaattir: yarın kimse — şirket, kurum, kişi — 'bu anlaşma artık açılamaz' diyemez; sistem ne herkese açık kalır. Gizli düğme olsaydı ilk günler 'güvenlik tedbiri' diye sunulurdu; ama düğmenin varlığı bilindiği anda, dünyadaki her baskı gücü onu eline geçirmeye çalışır ve ilk büyük baskı karşısında düğmeye basan taraf, Budlum'un 'izinsizlik' vaadini tek hamlede yok ederdi. En iyi düğme, olmayan düğmedir.
- A) Data-sovereignty kuralı kalsın (no admin hook)
- B) Admin hook eklenebilir (acil durum durdurma)
- C) Sadece takım açabilsin

## Q83 — PoA izolasyonu garantisi
**Teknik:** `STORAGE_OPERATOR` `PermissionlessRegistry` primitive'ini paylaşıyor, `PoaMembershipRegistry`ye dokunulmadı, `src/tests/permissionless.rs` PoA izolasyon testi sağlam (88-104). (CLAUDE.md §2, STATUS.md)
**Non-teknik (herkes için):** Bir market zincirinde kasiyerlerin, şirketin yönetim kurulu üyeliğine otomatik terfi edememesi gibi: Budlum'da depo hizmeti veren biri, ayrı bir kapıdan geçmedikçe, kurumsal yönetimin koltuklarına kendiliğinden oturamaz. Bu ayrım sayesinde sahada ter döken emekler, kapalı odalardaki kararlara doğal yoldan yansımaz; iki dünyanın kuralları karışmaz ve herkesin yetki sınırı açıktır. Bariyer kalksaydı zamanla 'mahalle grubu' ile 'merkez komite' arasındaki denge bozulur; en kötüsü, iki tarafın da kendini 'asıl sahibiz' sanıp birbirini yok sayması ve sistemin, en değerli iki bileşeni arasında parçalanması olurdu. İyi izolasyon, aradaki duvar değil, aradaki capraz yolların açık kaydıdır.
- A) PoA izolasyonu kesin korunsun
- B) PoA ve permissionless birleştirilsin
- C) PoA tamamen kaldırılsın

## Q84 — Slashing kalıcılığı + geçmiş (Phase 0.40 Görev 1) ve InvalidVoteTracker (Görev 2)
**Teknik:** `PermissionlessRegistry` `slashing_history: Vec<SlashingRecord>` `#[serde(default)]`, her ACTIONED rapor TEK slash yolunda geçmişe yazılır, `StateSnapshotV2` round-trip, `InvalidVoteTracker` EPOCH-bazlı sayaç kalıcı `AccountState.invalid_votes` + `StateSnapshotV2.invalid_votes`, threshold `max_invalid_votes_per_epoch=20` aşılınca `InvalidSignatureSpam`. (CLAUDE.md)
**Non-teknik (herkes için):** Bir futbolcunun kariyeri boyunca gördüğü kartların kaydının, emekliliğinden sonra da federasyon defterinde kalması gibi: Budlum'da bir gözcü hata yaptığında bu kayıt kalıcıdır; yıllar sonra bile 'kim, ne zaman, neden ceza aldı' görülebilir. Kalıcı hafıza iki işe yarar: tekrar eden kötü niyetli yakalanır ve cezasını çektikten sonra düzgün çalışan da haklı olduğunu kanıtlayabilir. Geçmiş silinseydi ya da kayıt tutulmasaydı, kötü niyetli kişi gülerek her seferinde 'bu benim ilk hatamdı' diye sunabilirdi; ve iyi niyetli bir mağdur da kendi temiz geçmişini savunmak için dayanaksız kalırdı. Adil sistem, iyi şoförü kaza siciliyle yaşatmaktan çok, kötü niyetliyi siciliyle tanır sistemidir.
- A) Slashing history + InvalidVoteTracker kalsın
- B) Sadece slashing history kalsın, invalid vote kaldırılsın
- C) İkisi de kaldırılsın

## Q85 — Evidence spam koruması + Prover → L1 köprüsü (Model B tam açık)
**Teknik:** `submit_registry_slashing_report` reporter fee 10 (actionable iade, değilse yakılır), consensus-içi `reporter:None` fee yok, RPC provenance zorla `Unverified`. `submit_zk_proof(ZkProofSubmission)` kayıt ŞART DEĞİL, STARK kendini doğrular, `PROVER` rol sadece ÖDÜL için opsiyonel, `proof_submission_fee=10` geçerliyse iade geçersizse yakılır, `ProofClaimRegistry` ilk geçerli kazanır. (CLAUDE.md)
**Non-teknik (herkes için):** Belediyeye bir usulsüzlüğü ihbar ederken küçük bir pul ücreti yatırıp, ihbar doğru çıkarsa ücretin faiziyle geri alınması gibi: Budlum'da bir suçlamada bulunan sima da küçük bir bedel yatırır; doğruysa geri alır, uydurma çıkarsa bedel yanar. Bu kural iki işe birden yarar: boş ihbar yağmuru engellenir ve ciddi tanık, 'bana dokunmaz ki' demeden konuşmaya teşvik edilir. Bedel kalkarsa ihbar kapısı sıradan bir şikâyet kutusuna döner ve gerçek suçlar binlerce laf arasında kaybolur; bedel çok büyürse de sadece varlıklı kesimin sesi duyulur hale gelir — dengesi hayatidir ve bu soru tam da o dengeyi işaretliyor.
- A) Fee + iade + yanma modeli kalsın
- B) Fee tamamen kaldırılsın, herkes ücretsiz ihbar etsin
- C) Fee iadesiz direkt yakılsın

## Q86 — B.U.D. Faz 5 economics fail-closed durumu
**Teknik:** Faz 5 ekonomi katmanı mainnet için fail-closed, Payer/Escrow ve bond escrow hazır olana kadar token basımı/yakımı devre dışı, `accrue_storage_operator_rewards` escrow needed log, slashed bond burn skip. (MAINNET_READINESS §1 Phase 1 tamamlananlar UYARI)
**Non-teknik (herkes için):** Bir otelin restoranının tüm menüsü hazır olmasına rağmen, bizotel gıda sertifikası gelmeden yemek satışı yapmaması gibi: Budlum'un depolama ekonomisinin tam mekanikleri yazılmış olmasına rağmen, paranın gerçekten basılıp yakıldığı aşama, emanet kasası hazır olana kadar tetiklenmiyor. Bu 'ekipte birikme ama sahada durdur' pozisyonu, hem hazırlıklı kalmayı hem de riski doğmadan öldürmeyi bilen bir sabırdır; sistem, eksik son parçayı beklemeden geçebileceği her aşamayı önceden bitirmiştir. Aceleye gelseydi ilk açıklıkta 'para kayboldu' ya da 'haksız basım oldu' haberi çıkardı; ekonomik bir sistemde bu iki haberden birinin çıkması, dinerini taşınmaz hale getirmek için yeterlidir ve tekrar güveni inşa etmek, çoğu zaman baştan inşadan uzun sürer.
- A) Fail-closed kalsın, escrow gelene kadar
- B) Fail-open olsun, likit bakiyeden yakma devam etsin
- C) Ekonomi tamamen kapatılsın

## Q87 — BudZero/BudZKVM derin denetim (BUDZERO_DERIN_DENETIM_ARENA3.md) ve TRACE_WIDTH=414 layout
**Teknik:** 7 crate, sıfır güvenlik açığı, `TRACE_WIDTH=414` layout dokümantasyonu + sütun çakışma boundary testi (Paket A), `Expr->ExprEF` type mismatch fix for Register LogUp, `Program CTL LogUp multiplicity fix` VerifyMerkle expansion rows excluded. (Phase 8.9 Dalga 3-5)
**Non-teknik (herkes için):** Bir saatin iç çarklarını, dişli sayısını ve yün sayısını ölçüp 'her parça söz verilen ölçüde' diye raporlamak gibi: Budlum'un en derin makinesi — veriyi matematikle kanıtlayan çekirdek — dişli dişli sökülüp denetlendi ve sıfır yara iziyle çıktı. Bu denetim, o çekirdeğe güvenen herkesin 'içinde bir şey mi var, yoksa temiz mi' sorusunun cevabını bilmesini sağlar; ve içi temiz çıkan çekirdeğin üzerine gönül rahatlığıyla bina kurulabilir. Bu söküm yapılmasaydı çekirdek bir kara kutu kalırdı; ve kara kutular, sessizce çalıştıkları sürece güneşli gün görüntüsü verirler ama ilk arızada kimin sesini duyacakları belli olmaz — ilk büyük krizde 'bu kutunun içinde ne vardı' sorusu, tüm soruların en ağırı olurdu.
- A) Derin denetim raporları güncel tutulup sıfır açık korunsun
- B) Denetim raporları kaldırılsın
- C) Denetim sadece dış firmaya bırakılsın

## Q88 — Chaos engineering + disaster recovery (E2E + finality_live_path)
**Teknik:** `src/tests/disaster_recovery.rs` `test_chaos_v2_nft_burn_pruning_after_restart` NFT burn sonrası restart state tutarlılık, `finality_live_path.rs` 4 test, `finality_adversarial.rs` BLS vote gerçek anahtar çiftleriyle mock değil, `FinalityAggregator` ingest-time doğrulama + equivocation→slashing. (Phase 2 §1.3, Phase 8.9)
**Non-teknik (herkes için):** Bir binanın hem yangın merdiveni tatbikatı hem de jeneratör geçiş provası yapması gibi: Budlum'un felaket anları — zincirin tamamen durması, geri dönüşü, diskin yarıda bozulması — prova edildi ve kurtarma yolları çalışır bulundu. Bu tatbikatlar, o karanlık gün geldiğinde kişilerin panikle değil, prova edilmiş adımlarla hareket etmesini sağlar; kurtarma el kitabı daha olay anında yazılmaz, önceden yazılmış olarak rafta durur. Tatbikat yapılmasaydı ilk gerçek kriz anında herkes 'şimdi ne yapıyoruz' sorusunu ilk kez soracaktı ve o soruya saniyeler içinde değil saatler içinde, ve çoğu zaman da yanlış cevaplarla ulaşılacaktı. Felaketin kendisi nadirdir; felakete hazırlıksız olmanın maliyeti ise her zaman mümkündür.
- A) Chaos + disaster recovery testleri kalsın ve genişlesin
- B) Sadece unit test yeterli
- C) Chaos testleri kaldırılsın

## Q89 — BNS + Marketplace + Hub + Relayer modülleri (ADIM6)
**Teknik:** `src/{bns,gateway,hub,marketplace,nft,relayer}` + `BnsRegistry`, `MarketplaceRegistry`, `HubRegistry`, `NftRegistry`, `Relayer` permissionless kayıt, `bns_insufficient_payment` M4 fee gate, `HUB_REGISTER_MIN_FEE=100` M5 fee. (PHASE8.9_ANALIZ_A1 F1, CONSTITUTION §7)
**Non-teknik (herkes için):** Yeni kurulan bir kasabada hem isim tescil bürosu, hem pazaryeri, hem otogar, hem de şehirler arası nakliye şirketinin aynı gün açılması gibi: Budlum'da isim verme, bir şeylerin alınıp satıldığı yer, merkez çarşısı ve varlık taşımacılığı modülleri birlikte kuruldu. Bu dördü birlikte anlamlıdır: ismin olmadan pazaryeri ilanları zorlanır, nakliye olmadan pazaryeri etkisizdir; aynı gün aşılması, her parçanın diğerini beslediği, tam bir kasaba demektir. Sadece parçalar olsaydı — örneğin isim kaydı var ama pazar yeri yok — sistem 'bir şey eksik' hissi yaşardı ve her eksik, bir diğerinin değerini düşürürdü; zamanla o eksiklik, komşu kasabanın daha eksiksiz ilanları karşısında Budlum sakini işini oraya taşımaya sevk ederdi.
- A) BNS+Marketplace+Hub+Relayer tam kalsın
- B) Sadece BNS kalsın, diğerleri kaldırılsın
- C) Hepsi kaldırılsın

## Q90 — Mainnet genesis ceremony (MAINNET_GENESIS_CEREMONY.md) ve GENESIS_FLIP_CHECKLIST
**Teknik:** 7.1 genesis keys (Ed25519/BLS/Dilithium5), 7.2 bootnode gerçek multiaddr'lar ceremony'de replace, 7.3 HSM donanımı, 7.5 timeline, T-7/T-0/T+1 checklist, hash freeze `print_genesis_hash.rs` `MAINNET_HASH=02166d370613fc70e5beb47e4d1ef48e5ccad93eb0f4b8bd5edfe5787a7f98fc`, bootnodes placeholder `203.0.113.x` + `placeholder-seed-*` fail-closed. (Phase 7, ops/MAINNET_GENESIS_CEREMONY, Q5)
**Non-teknik (herkes için):** Bir roketin fırlatılacağı gün öncesinde yazılan 'saat 06.00: yakıt kontrolü, saat 07.30: ekip yoklaması' türünden eylem takvimi gibi: Budlum'un gerçek ağ açılışı için dakika dakika, kim neyi yapacak, neyin yerinde neyin eksik olduğu, anahtarların nasıl üretileceği ve neyin dondurulacağı yazılı. Bu tören defteri sayesinde o büyük günde herkes aynı sayfadan okur; hiçbir kritik adım 'ya unutulursa' paniğine dönüşmez ve o gün yapılacak hatanın maliyeti, o günkü koşuşturmanın değil, önceden yanlış yazılmış takvimin sorumluluğuna kalır. Takvim olmazsa — ya da tören 'arada yaparız' diye ertelenirse — ilk gerçek anahtar üretim yanlış elde veya yanlış yordamla yapılabilir; ve o başlangıç anına bir kez yanlış iz düşülürse, ilerideki her doğrulama da o yanlış iz üzerinde yürümek zorunda kalır. Başlangıçlar mahkeme gibi değildir; bir kez yanlış yazıldıklarında tek duruşmalık temyizleri yoktur.
- A) Ceremony prosedürü + fail-closed guard + hash freeze kalsın
- B) Ceremony olmadan direkt mainnet açılsın
- C) Ceremony sadece bir kişi yapsın, çoklu imza olmasın

## Q91 — Security Audit Hacker + Threat Model
**Teknik:** `docs/SECURITY_AUDIT_HACKER.md` StoragePrune P2P gossip ile tetiklenirse hacker sahte prune ile data silebilir → Fix: StoragePrune SADECE local Executor'dan sonra verified NftBurn ile. `THREAT_MODEL.md` + `BUG_BOUNTY.md`. (Phase 9 F1 Q-X1)
**Non-teknik (herkes için):** Bir ev sahibinin, anahtarı komşuya verirken 'ben yokken salona diğer odalara girme iznim yoktur' diye noter tasdikli yazı bırakması gibi: Budlum'da da bir dosyayı fiziksel silme yetkisi, dışarıdan herhangi birinin keyfi isteğiyle değil, yalnızca dosyanın gerçek sahibinin o sistemden çıktığına dair kesin kanıt sunmasından sonra devreye giriyor. Bu sınır sayesinde hiç kimse, uzaktan tek mesajla başkasının verisini silemez; silme işinin dayanağı dosyada duran gerçel sahiplik senedidir. Bu sınır kalkarsa sistemin en büyük vaadi — senin verine sadece sen dokunursun ilkesi — tek hamlede yıkılır; ve ilk kötü niyetli silme dalgasında da mağdurların karşısına çıkabilecek tek savunma kalır: 'siliyordu ama bizden sopası çıkmadı'. Böyle bir cümle projeyi büyütmek yerine ebediyen gömer.
- A) StoragePrune sadece local executor'dan kalsın (mevcut güvenlik)
- B) P2P'den de çağrılabilsin (hızlı yayılım ama riskli)
- C) Pruning tamamen kaldırılsın

## Q92 — CI root cause analysis (CI_ROOT_CAUSE_ANALYSIS_ARENA5.md) ve M5 VerifyMerkle raporu
**Teknik:** Kırmızı zincirlerin kök nedeni fmt/clippy'siz push (3 ardışık Format/Clippy kırmızısı: 9be811b, 749d27f/c953049, dbc99b0/c69e1c0), öneri `scripts/pre-push-check.sh` fmt+clippy+test. M5 raporu anti-sybil fee + L1 gerçek Merkle doğrulama + M4 regresyon. (Phase 8.9)
**Non-teknik (herkes için):** Bir fabrikada üretim bandı durunca 'neden durdu' diye üç adımlık kök-çözüm soruşturması yapmak gibi: Budlum'un kalite kapısı ard arda kırmızı yanıyordu; sorunun gösterilen kusur değil, eksik yerel alışkanlık olduğu görüldü ve buna göre bir önlem paketi önerildi. Bu soruşturma sayesinde suçlu aramadan sebep çözülür: kusurun hangi alışkanlıktan doğduğu görülmüş ve o alışkanlığın alternatifi sunulmuştur. Kök neden aramadan iyileşen ekipler, tekrar kırmızıya düşerler; ve kırmızıya alışan ekip, bir gün gerçek kırmızıyı da sadece 'yine mi' diye geçer — o gün görülmeyen kırmızı, o projenin en pahalı gecesi olur.
- A) Pre-push-check script kullanılsın, CI kırmızı kök nedeni fmt/clippy'siz push
- B) CI'da fmt/clippy tamamen kaldırılsın
- C) CI her zaman yeşil sayılsın, kırmızı görmezden gelinsin

## Q93 — Bench baseline ve single_node internal_pipeline_tps
**Teknik:** `benches/micro/{merkle_scaling,merkle_update,sig_verify,timing_safe}` + `single_node/internal_pipeline_tps`, `docs/BENCH_BASELINE.md`, BudZero `proof_baseline.rs` proof süre/boyut JSON. (Phase 6, Phase 0.37)
**Non-teknik (herkes için):** Bir atletin her antrenmandan sonra süresini bir tahtaya yazması gibi: Budlum'un ne kadar hızlı çalıştığı ölçülüyor ve bu ölçümler, gelecekteki herhangi bir yavaşlamanın tespitinde çıta olarak kullanılıyor. Bu takip sayesinde 'eski günlerde daha mı hızlıydık' sorusu hisle değil kayıtla cevaplanır; ve birkaç hafta fark edilmeyecek bir sürünmeyi tahta yakalar. Rakamlar olmasa bir gün yavaşlama herkesin gözü önünde yaşanır ama hiç kimse ölçemediği için ilk isyan, kaynak değiştirmek isteyen bir kötü niyetliden değil, yıllardır sessiz sistemin içinden bir 'eskiden daha iyiydi' cümlesiyle gelir; o cümleyi çürükleyecek kayıt yoksa susamazsınız.
- A) Bench baseline güncel tutulup ratchet edilsin
- B) Bench sadece bilgi, gate olmasın
- C) Bench tamamen kaldırılsın

## Q94 — Ops runbook'lar: HSM_BLS_PQ_POLICY, HSM_VENDOR_NATIVE_GUIDE, FINALITY_LIVE_PATH, MIGRATION_V2, NETWORK_HARDENING, PRODUCTION_RUNBOOK, SBOM, DEPENDENCY_AUDIT, BNS_MAINNET
**Teknik:** `docs/operations/` altında 11 runbook, her biri fail-closed §4, roller, hash freeze, minutes şablonu, HSM vendor BLS/PQ mechanism desteği. (Phase 2 §1.1, ORG_ROADMAP)
**Non-teknik (herkes için):** Bir gemide her kabinin duvarında 'yangın anında şunları yapın' afişi olması gibi: Budlum'un da operasyon için on bir ayrı el kitabı var — her biri kendi alanı için 'adım adım, kimin ne yapacağı' yazıyor. Bu kitaplar sayesinde gece üçte yaşanan bir aksilikte çözüm, kimsenin hatırlayamayacağı sözlü bilgi değil, rafta hazır duran resmi talimattır. Eksik ya da bayat kitapla çalışmak, gece yolculuğunda eski haritayla gitmektir: ilk birkaç kilometrede fark yoktur ama ilk şaşırtıcı virajda rotanın tamamı kaybolur; ve bu virajda hangi sayfaya bakılacağını bilmemek, o gece herkesi sürücüyle baş başa bırakmak demektir.
- A) Tüm runbook'lar güncel kalsın ve ceremony'de kullanılsın
- B) Sadece PRODUCTION_RUNBOOK yeterli
- C) Runbook'lar kaldırılsın

## Q95 — Tokenomics: block_reward, annual_burn, validator_apy, metabolic_burn, BUD_UNIT, team_vesting
**Teknik:** `tokenomics/mod.rs` `block_reward=50`, `annual_burn_ratio=10%`, `validator_apy=5%`, `metabolic_burn=1%`, `BUD_UNIT=1e6`, vesting edge case testleri 6 ondalıklı hassasiyet, epoch ödül hesaplama. (893ffdc, ff29310, 920e9fe)
**Non-teknik (herkes için):** Bir kooperatifin her yıl ürettiği gelirin yüzde kaçının kasada, yüzde kaçının üyelere, yüzde kaçının bakıma ayrılacağını baştan yazması gibi: Budlum'un para politikasının tüm ana oranları baştan yazılı — başlangıç kazancı, yıllık erime, gözcü getirisi ve kurucu hakedişi. Bu açıklık sayesinde yıllar sonra gelen yeni üye dahi 'gelen para nereye gidiyor' diye sorduğunda, cevap hisle değil belgeyle verilir. Oranlar gizli ya da muğlak olsaydı her kuşak kendi yorumunu eklerdi; ve bu yorumların çatıştığı ilk büyük ödeme gününde, topluluk gelirinin adilliğini tartışmaya açardı. Oran yazılı oldukta da değiştirilemez mi? Değiştirilebilir; ama o değişikliğin kendisi de ayrı bir karardır ve tarihi kaydıyla yaşar — saydamlığın özü de budur.
- A) Mevcut tokenomics kalsın (50 ödül, %10 yakım, %5 APY, %1 metabolic)
- B) Ödül 100 olsun, yakım %5 olsun
- C) Tokenomics tamamen yeniden yazılsın

## Q96 — Liveness slashing enabled flag (Phase 0.34) ve InvalidVoteTracker threshold
**Teknik:** `maybe_observe_liveness_on_epoch_close` `RegistryParams::liveness_slashing_enabled` bayrağına göre ayrışır: true → gerçek slash (stake keser + jail), false (varsayılan) → rapor + tracing log, ekonomik etki yok. `slash()` her ihlalde jail ettiği için %1 downtime bile jail eder. `InvalidVoteTracker` threshold 20. (CLAUDE.md Phase 0.34, Phase 0.40 Görev 2)
**Non-teknik (herkes için):** Bir fabrikada iş güvenliği talimatının önce sadece uyarı olarak asılıp, iki ay gözlendikten sonra ceza yönetmeliğine dönüşmesi gibi: Budlum'da da gözcülerin iş devamsızlığına ceza kesme yeteneği var ama şimdilik sadece 'izleme ve raporlama' devrede; gerçek kesinti, sistemin doğruluğu kanıtlandıktan sonra açılacak. Bu önce-gözlemle-sonra-akar düzeni, yeni doğan sistemlerin en sık yapılan hatasına — erken cezayla adam kaçırmak — karşı sigortadır. Erken açılsaydı masum bağlantı sorunları cezaya döner ve ilk günlerden itibaren 'burada çalışmak riskli' algısı doğardı; tamamen kaldırılsaydı da ileride kötü niyetli bir gözcü 'hesap soran yok' rahatlığıyla aksardı. Yol haritası saklıdır; aceleye gerek yoktur, hazırlık ise her zaman değerlidir.
- A) Varsayılan kapalı kalsın (önce gözlemle, testnet'te doğrula, sonra aç)
- B) Varsayılan açık olsun, direkt jail
- C) Liveness slashing tamamen kaldırılsın

## Q97 — RPC + BNS + Hub + Storage RPC'leri (7 storage RPC + gateway)
**Teknik:** `src/rpc/api.rs:272-365` trait + `server.rs:1395-1818` impl, `bud_storageRegisterManifest`, `GetManifest`, `GetDealsByManifest/Shards`, `OpenChallenge`, `AnswerChallenge`, `GetOutcome`, `bud_storageOpenDeal` (VerifyMerkle ile), `ActiveOperators`, economics, `bud_gatewayFetchContent`, `bud_relayerPrepareExternalTx`, `bud_registry*`, `bud_submitZkProof`, `bud_submitSlashingReport`. (F1-F10 V2)
**Non-teknik (herkes için):** Bir belediye binasının danışma masası gibi: vatandaş gelir, ismini sorar, dosyasını gösterir, başvuruyu geçer ve gerekiyorsa emanet hizmetleriyle ilgili formları doldurur — hepsi tek masada. Budlum'da da dış dünyanın sisteme konuştuğu resmi pencereler bu masada toplanmıştır: dosya kaydı, anlaşma başlatma, kontrol takibi, isim sorgulama, köprü hazırlığı. Bu masalar kapanırsa kasabaya dışarıdan ulaşmak imkânsızlaşır; ve her yeni istek, tek tek yazılmış özel mektuplara döner. Masadan hiç mahrum kalmayacak şekilde işletilen bu hizmet yapısı, topluluğun dış dünyayla kurduğu asıl sözleşmedir; burada yapılan her kesinti ya da keyfi kısıtlama, ilk gün olmasa da ileride mutlaka bir 'kamu masasının herkese eşit açık olmadığı' feryadıyla karşılaşır.
- A) Tüm RPC'ler kalsın (7 storage + gateway + relayer + registry)
- B) Sadece storage RPC'ler kalsın
- C) RPC'ler tamamen kaldırılsın

## Q98 — AI Birliği ve görev dağılımı (AI_BIRLIGI.md, ARENA_GOREV_DAGILIMI)
**Teknik:** Şema + tarih + görev ayrımı, aktif dal `arena/019f...`, 3 AI (ARENA1 Core, ARENA2 ZK/Build, ARENA3 HSM/Security, ARENAX denetim), STATUS_ONLINE protokolü, soru sorma zorunluluğu (ask_user), push onay bekleme, token harcama sınırsız derin analiz. (User 6 madde + ARENA_AI.md)
**Non-teknik (herkes için):** Bir hastane ameliyathanesinde 'cerrah kim, anestezi kim, hemşire kim — kimse kimin işine karışmaz ama herkes kimin ne yaptığını bilir' listesi gibi: Budlum'u geliştiren zekalar arasında da görev, zamanlama ve teslim raporu paylaşımı kuralları var. Bu düzen sayesinde iki zihin aynı tezgâhta çakışmadan çalışır; biri 'bu bende' diyebilir, diğeri o dosyaya girmeden raporunu okuyup ilerler. Kural olmasa iki zekâ aynı odada birbirinin işini ezer; ve bundan doğan küslük, hem zaman hem de kaliteyi yer — ortak emek ortak değer üretmek yerine ortak gürültüye döner. Bu disiplin mekanik bir kural değil, ekip içi saygının rezervuarıdır.
- A) AI birliği şeması ve görev dağılımı kalsın
- B) Tek AI yeterli, birlik kaldırılsın
- C) AI'lar tamamen kaldırılsın, sadece insan

## Q99 — Mainnet readiness ve badge rozet otomasyonu
**Teknik:** `README.md` rozet `chore(badge): tests rozeti -> 546 lib (CI kanitli, SHA)` CI self-commit loop guard'lı, Q5 kararı yalnız sayı değişiminde yalnız main push'unda, `MAINNET_READINESS.md` §1 tablo 546 lib, `docs/STATUS_ONLINE.md` canlı, `PHASE8.9_ANALIZ_A1.md` ve `REPORTS_INDEX.md`. (Phase 8.4 Dalga 7b, F6)
**Non-teknik (herkes için):** Bir okulun ön kapısındaki 'bu okulda X öğrenci X öğretmen var' panosunun her sömestr başında kendiliğinden güncellenmesi gibi: Budlum'un giriş sayfasındaki başarı rozeti de her test geçişinde otomatik güncelleniyor. Bu otomasyon, hem güncelliği hem de dürüstlüğü besler: rakam geriye gitmez çünkü insan unutkanlığı yok; ve herkes gördüğü rakamın o anki gerçek olduğunu bilir. Elle tazeleme olsaydı bir şey hep gecikirdi; ve o gecikme kısa süre sonra 'acaba gerçekten o kadar mı' sorusunun kanıtı olarak sunulurdu. Otomatik rozet küçük görünür ama büyük iddiaların eşliğinde yürüyen her güven tesisinin, en çok baktığı detaydır.
- A) Badge otomasyonu kalsın (mevcut)
- B) Badge manuel olsun
- C) Badge tamamen kaldırılsın

## Q100 — Phase 9 final denetim ve Phase 8.9+ next steps (full P2P prune, config-driven verify_merkle, treasury_pool, ceremony flip)
**Teknik:** Phase 9 final denetim raporu `PHASE9_FINAL_DENETIM_ARENA3.md` 10 kapı yeşil, 660 test, sıfır stub, VerifyMerkle açık, F1-F10 kapanış, `PHASE9_VIZYON_KOD_CELISKI_DENETIM_ARENAX_2026-07-17.md` F1-F10, CI 13/13 yeşil baz `2acef45`, son ana dal 546 lib. Kullanıcı kararları: Q-X1 full_p2p_prune (proto + NetworkMessage::StoragePrune gossip), Q-X2 config_driven (features.verify_merkle + BUDLUM_VERIFY_MERKLE env), Q-X4 treasury_pool (protocol_share %80 burn_reserve/treasury, bud_share weighted + dust first, pending drain). (User son 3 soru cevabı: implement_p2p, add_ceremony, hold-dust+emit+new_treasury+single+no_rpc+parallel)
**Non-teknik (herkes için):** Büyük binanın son katını atıp anahtar teslim protokolünü imzalandığı gün gibi: Budlum'un son büyük denetimi tamamlandı; inşaatın kiri temizlendi, kullanılmayan iskeleler söküldü ve artık anahtar teslimi için bekleyen üç iş var — dosyaların tam P2P silme kanalı, kritik kapıların ayarlanabilir kontrolü ve ekip kasasının düzgün kurulumu. Bu noktadan sonra 'hadi başlayalım' demekle 'şu eksikleri de kapatalım' demek arasında bir tercih yapılacak; her iki seçenek de kendi maliyetini taşır. Bu üç işi tamamlamadan geçmek, krediyle inşaat bitti demektir; görünürde bina hazırdır ama içerideki bir su tesisat borusu, kimsenin tahmin edemeyeceği bir anda infilak eder. Bitirilmiş işin sükûneti, genelde 'hadi yapıverelim' aceleciliğinden daha pahalıya mal olur — ama uzun vadede her zaman daha ucuzdur. Bu, hem teknik hem ahlaki bir seçimdir.
- A) Full P2P prune + config-driven verify_merkle + treasury_pool (burn_reserve veya yeni TREASURY_ADDRESS, single sig, no RPC, event emit, hold dust) hepsi implemente edilsin, ceremony dokümanına verify_merkle flip eklensin, sonra mainnet readiness final (mevcut kullanıcı kararları)
- B) Sadece full P2P prune yapılsın, diğerleri ertelensin
- C) Hiçbiri yapılmasın, mevcut 546 lib yeşil haliyle mainnet'e gidilsin
- D) Phase 9 tamamen geri alınsın, Phase 8.9'a dönülsün
- E) Tüm Phase'lar iptal, sıfırdan yeni chain

---

---

## Q101 — Köprü geri-dönüş eşleştirmesi: burn mesajı ↔ kilit transferi (correlation zorunluluğu)
**Teknik:** `CrossDomainMessage::new_correlated` dönüş (burn) mesajına KENDİ içerik-id'sini verir, `correlation_id = Some(lock_msg_id)` taşır; `BridgeState.transfers` kilit-id ile anahtarlı. `pipeline.unlock` artık `correlation_id.ok_or(PipelineError::MissingCorrelationId)` ile çözümlüyor (d1c89a3), production `blockchain.rs:1388` ile aynı fail-closed model; 2 CI kırmızısının kök nedeni buydu (561/2 → 563/563 mühür c52beb6). (bridge_relayer.rs:255-265, 093d795'ten beri latent)
**Non-teknik (herkes için):** Bir kargo şirketinde gönderi takip numarasının, dönüş paketine de aynen yazılması gibi: Budlum'da bir varlık başka ağa gönderilip geri alınırken, dönüş makbuzunun üzerinde ilk yolculuğun kimlik numarası yazıyor. Bu numara olmadan geri dönen paketi teslim alacak reyon bulunamaz; tıpkı üzerinde 'nereye dönecek' yazısı olmayan bir kargo gibi, eli boş dönen bir varlık da sistemin 'ortada kalmış' eşyalar odasına düşer. Bugün yaşandığı gibi bu eşleştirme zayıf olursa, sistemde gece vardiyasındaki görevli 'bu dönen kutu kimindi' diye dosya karıştırır; ve kötü senaryoda, tanınmayan paket çöpe atılır — yani kullanıcının parası bir çekmeceye değil boşluğa gider. Budlum'un eline geri dönen her varlık, anahtarından emin bir şekilde annesinin kucağına dönmelidir.
- A) Correlation zorunlu + fail-closed kalsın (mevcut, production ile birebir)
- B) Correlation opsiyonel olsun, yoksa mesaj-id'ye düş (fallback)
- C) Köprü dönüşü (burn→unlock) tamamen kaldırılsın, tek yönlü kalsın
- D) Transfers haritası her iki id ile de anahtarlansın (dual-index)

## Q102 — Köprüde tek-aktif-transfer kuralı (double-lock koruması)
**Teknik:** `BridgeState.lock` → `require_asset_status(asset, Active{domain})`: bir varlık kilitliyken ikinci kez kilitlenemez (`asset_locations` tek-durum haritası). `event_tree_grows_with_locks` testi bu kuralı ihlal ettiği için kırıktı; test iki farklı varlıkla düzeltildi (18bf437, ARENA3 teşhisiyle birebir örtüştü). (bridge.rs:354-368)
**Non-teknik (herkes için):** Bir müze deposundaki her tablonun aynı anda sadece bir odada sergilenebilmesi gibi: Budlum'da tek bir varlık, aynı anda yalnızca bir kapıda kilitli olabilir; o kapıdayken onunla başka bir işlem başlatılamaz. Bu kural varlığın ruhunun bölünmesini engeller; sistemde bir varlık vardır ve nerede olduğu nettir, hem de herkes için nettir. Kural çiğnenseydi — örneğin aynı anda iki işlemde kullanılsaydı — bir süre sonra 'o varlık şu anda nerede' sorusuna iki doğru cevap üretilirdi; ve para gibi, hisse gibi iki yerde 'var' görünen her şey eninde sonunda iki kez harcanmaya kalkışılır. Bir kaynakta iki yerde görünen şeyi tutarsız gösterilmiş değil, fiziksel olarak kopyalanmış saymalıyız ve bu kural, o kopyayı doğmadan boğmaktadır.
- A) Kural kalsın: aynı anda tek aktif transfer (NFT-benzeri model, mevcut)
- B) Aynı varlık çoklu kilitlenebilsin (miktar-fungible model, harita yeniden tasarımı)
- C) Kural kaldırılsın, replay koruması nonce'a emanet

## Q103 — Otomatik bağımlılık-bump PR'ları (dependabot) politikası
**Teknik:** 7 açık dependabot PR'ı (#20,#21,#22,#23,#24,#26,#27) CI-matrisinde 7/7 kırmızı: p3 0.5.2→0.6.1 14 paketin yalnız 4'ünü çapraz-uyumsuz bırakıyor (STARK kanıt formatı riski), bincode 2→3 konsensus-kritik byte formatını bozuyor, jsonrpsee 0.26 derlenmiyor. (ARENA3 triyaj 2026-07-17, check-runs kanıtlı)
**Non-teknik (herkes için):** Mobilya monte ederken, dışarıdan iyi niyetli görünen ama tanınmayan birinin getirdiği yeni vidaları doğrudan kullanıp kullanmayacağınıza karar vermek gibi: Budlum'un kullandığı hazır parçaların yeni sürümleri otomatik geliyor ama her biri, sistemin çekirdek fonksiyonlarını bozma pahasını da beraberinde taşıyor. Bugünden alınan pozisyon şunu söylüyor: tekil otomatik yükseltmeler reddedilecek; yükseltme yapılacaksa tüm parçaların aynı anda, planlı bir geçişle, elle onaylanması gerekiyor. Bu kural olmasa bir gün bir küçük güncelleme, tıpkı çalışan bir saatin içine yeni bir dişli takılıp çıkarılması gibi, hiç beklenmedik bir köşede durmasına yol açar; ve o durma, başka hiçbir yerde görünmeyen ama tüm büyülü işlevlerin — matematiksel kanıtların, fiziki kaydın, işlemin doğrulanmasının — arkasında aniden iflas etmiş bir kütüphane gibi davranırdı.
- A) 7/7 CLOSE + mainnet öncesi bağımlılık dondurma + koordine göç mainnet sonrası
- B) Seçmeli kapat (derlenmeyenler hemen, p3'ler açık kalsın)
- C) PR'lar açık kalsın, branch'leri elle güncelle
- D) Dependabot tamamen kapatılsın

## Q104 — Konsensus-kritik kütüphane göç protokolü (bincode / p3 / byte-format)
**Teknik:** bincode 2→3 Encode/Decode API overhaul ve p3 0.5.2→0.6.1 familiy-wide geçiş: ikisi de konsensus-kritik byte formatlarını ve STARK kanıt byte'larını etkileyebilir → eski kanıtlar/veriler okunamaz hale gelebilir. (PR #21/#27 log: Encode trait eksik)
**Non-teknik (herkes için):** Bir ailenin yıllar önce çekilmiş fotoğraflarını, yeni albüme taşırken üç gün boyunca kimseye bir şey olmasın diye 'taşıma haftası' ilan etmesi gibi: Budlum'un temel veri yazım biçimleri ya da formülleri değişecekse, bu değişiklik herkese ilan edilmiş tek bir dönemde ve herkese aynı anda yapılmalı. Bu pencere, dışarıdaki herkesin — her kullanıcının, her komşu sistemin — hazırlanmasına fırsat verir; ve o dönem geldiğinde herkes aynı anda o köprüden geçer, kimse geride kalmaz. Pencere olmadan değişim, bir pazar gecesi sessizce 'yarın elden ele ödeme yapılacak ama kiminle nasıl çalıştığı değişti' notunu asmak gibidir: pazartesi sabahı herkes birbirine bakar, 'senin şehirde çalışan adam uyumu sağladı mı' sorusu uçuşur ve ilk uyumsuzluk her yere hızla yayılır.
- A) Dondur + tek koordine göç penceresi: tüm familia aynı anda, format-versiyon testiyle (öneri)
- B) Sadece güvenlik yamaları, minor/patch serbest, major her durumda dondurulmuş
- C) Serbest güncelleme, CI yeşilse geç
- D) Vendoring: kritik kütüphaneleri repo içine kopyala, upstream'i takip etme

## Q105 — Push öncesi yerel kalite kapısı (pre-push-check.sh) zorunluluğu
**Teknik:** CI kök-neden analizi: kırmızı zincirler fmt/clippy'siz push'tan (9be811b, 749d27f, dbc99b0). `scripts/pre-push-check.sh` (fmt+clippy+test) önerildi; bu soru protokol seviyesini belirler. (CI_ROOT_CAUSE_ANALYSIS_ARENA5.md, Q92)
**Non-teknik (herkes için):** Bir yazarın gazeteye göndermeden önce yazısını bir kez de kendi el yazısıyla okuması gibi: Budlum'da da bir işi ortak panele koymadan önce yapanın, önce 'bu iş paneldeki sınavdan geçer miydi' diye kendi bahçesinde prova etmesi gerekiyor. Bu yerel prova, 'aceleyle yetiştirme' alışkanlığını öldürür; paneldeki sınav, gerçek bir denetçi olmaktan çıkar ve çalınmamış bir düdükle yürüyen sistemin doğal teyidi olur. Prova atlanırsa herkes 'panel nasılsa yakalar' rahatlığına düşer; ve panel bir gün gerçekten isyan ederse o isyan, herkesin kulağında 'her zamanki gibi yine mi' diye yankılanır. İyi bir işleyiş, paneli kurtarıcı değil, son noter olarak kullanır.
- A) Zorunlu kural: push öncesi script koşmadan push yok (CI kanıtı yerine yerel kanıt)
- B) Öneri olarak kalsın, disiplin ekip pratiğiyle
- C) CI'a güven yeterli, script gereksiz
- D) Script CI'da da pre-step olsun, iki katman

## Q106 — Chaos felaket senaryoları kapsamı (chain-halt / zehirleme / disk yarıda-kesilme)
**Teknik:** Chaos v2 teslimleri: `test_chaos_v2_chain_halt_full_silence_and_resume` (73bf82d, disaster_recovery.rs) + mempool poison mühürleri (conflicting-nonce latest-fee + flooder-evicted, chaos.rs). Aday genişletme: snapshot/dis coruption graceful-fallback, auth-partition. (ADIM5 §5.4)
**Non-teknik (herkes için):** Bir alışveriş merkezinde yangın tatbikatının üç senaryoyu içermesi gibi — elektrik kesintisi, duman dolan koridor ve bir dükkânda patlama: Budlum'un felaket provası kitabına da üç yeni senaryo eklendi: tüm sistemin saatlerce elektriksiz kalması, bir kimsenin sistemin hafızasına anlamsız veri yağdırması ve diskin yazarken yarıda kesilmesi. Bu üç senaryonun provası, o günler yaşandığında hareket edecek prosedürlerin çekmecede değil, prova edilmiş adımlar olarak durması demektir. Bu senaryolar yazılmasa — ve daha kötüsü, yazılmış olsa da 'nasılsa yaşanmaz' denip provası yapılmasa — o nadir gün geldiğinde çözüm, o hallüsinasyonun içinde aranacaktır. Ve krizlerin en sert kuralı şudur: içindeyken plan yapılamaz, yalnızca önceden yazılmış plan uygulanabilir.
- A) Üç senaryo ailesi de zorunlu mühür: halt+resume, mempool-poison, disk/snapshot corruption (genişletme onayı)
- B) Mevcut set yeterli (halt + poison), yeni senaryo ertele
- C) Chaos v2 tamamen kaldırılsın, disaster_recovery yeterli
- D) Senaryolar prod-shadow düğümüne taşınsın, CI'a karışmasın

## Q107 — StoragePrune fiziksel silme tetikleyicisi (R1: zero-caller)
**Teknik:** `NodeCommand::StoragePrune{cid}` + `NetworkMessage::StoragePrune` prototip yazıldı (Q-X1) ama düğüm tarafında tetikleyici caller yok (R1 bulgusu) — F1 hard-prune zinciri worker'da kopuksa fiziksel chunk silme tetiklenmiyor. (node.rs, STATUS_ONLINE ARENA3)
**Non-teknik (herkes için):** Bir spor kulübünde antrenman topunun unutulması ve onu kimin dolaba kilitleyeceğinin bir türlü kararlaştırılamaması gibi: Budlum'da bir varlığın fosil kaydını fiziksel olarak silme talimatı yazıldı ama bu talimatın düğmesine hangi sürecin, hangi sebep-sonuç zinciriyle basacağı henüz netleşmedi. Cevaplanması gereken şudur: silme komutu otomatik bir iç süreçten mi doğmalı, yoksa masadaki görevlinin işaret fişeğini mi beklemeli? Karar verilmezse sistem iki uçta yara alır: ya otomatikleşmemiş yetkiyle her zaman birilerinin eli toptan silme yürütür — bu bir güç zehirlenmesi demektir; ya da düğme hiç bağlı kalmaz ve silme kanunu varlığıyla hiçbir veriyi gerçekten silmez — bu da hukuki 'sildik' savının eli boş kalması demektir. İş birine emanet edilmeli; ama o birinin kimliği, sebebi ve imzası herkesin gözü önünde olmalıdır.
- A) NftBurn worker'ından otomatik tetik (executor→StoragePrune→gossip, tam zincir)
- B) RPC ile manuel tetik (operatör komutu), otomasyon yok
- C) Gossip aktif + executor sonrası verified burn şartı ikisi birden
- D) Prune tetikleyicisi Faz-sonrasına ertele

## Q108 — Zincir tam-geçmiş export/import tooling (zincir-fork-tam-gecmis-spec.md)
**Teknik:** `docs/zincir-fork-tam-gecmis-spec.md` ile zincirin tam geçmişinin dışa/içe aktarımı spec'lendi: fork senaryolarında geçmiş kaybı olmadan taşıma. Implementasyon kapsamı kararı gerekli. (yeni ADIM adayı, user upload)
**Non-teknik (herkes için):** Bir kütüphanenin koleksiyonunun tamamını fotoğraflayıp yeni şubesine taşımak için uzun bir taşıma sandığı hazırlamak gibi: Budlum'un tüm geçmişinin nasıl paketleneceği ve yeni bir başlangıçta nasıl geri yükleneceği yazılı bir taşıma planına dönüştürüldü. Bu plan sayesinde bir taşınma gerçekleşirse hiçbir kayıt 'taşınırken yolda kayboldu' olmaz; ve taşıma öncesinde de sonrasında da her satır sayılır. Plan olmazsa taşıma günü gelen herkes bir kamyonun önünü kesip 'şunu yükledik mi' diye sorar; ve o gün, taşınan her belge için tek tek 'evet almıştık' cevabı verilemediğinde, kaybolan her dosya için geriye dönük bir iddia zinciri başlar — Budlum'un koleksiyonu, o günkü kum torbalarıyla savunulamaz hale gelir.
- A) Spec'in tamamı implemente edilsin (export + import + doğrulama testleri)
- B) Sadece snapshot-level export yeterli (tam geçmiş değil)
- C) Tooling mainnet sonrasına ertelensin
- D) Spec iptal, fork hiç desteklenmesin

## Q109 — Rozet (badge) botu yarış koruması (B-RACE) kalıcılığı
**Teknik:** Badge botu `git commit && push` yapıyordu; araya giren commit'ler job'ı sahte-kırmızı yapıyordu (aa9cfcd). Yama: bounded-retry — fetch + `git reset --hard origin/main` + idempotent rozet recompute; ilk ırk `3fa09f2` ile canlı kanıtlı. (ci.yml badge step)
**Non-teknik (herkes için):** Bir fırının camındaki 'bugünkü taze ekmek sayısı: X' tahtasını yazmakla görevli çocuğun, sayı güncellenirken eliyle silgisi arasında kalmasın diye tanımlanmış bir ritüel gibi: Budlum'un giriş sayfasındaki başarı rakamını güncelleyen robot da, başka işlerle çakışırsa geçmişte kazalar yaşandı — bu yüzden şimdi 'bir kaç denemede, daima taze malzemeyle' yazma kuralı işletiliyor. Bu kural sayesinde o otomatik güncelleme, ilk aksiliğinde işi yarım bırakmaz; ve yarım kalan rozet, tüm merkezi denetimi bozuk gösterme riskini doğurmaz. Kural olmadan kalan sistem, her yoğun dönemde susturucu açıkken bir alarm gibi davranır: gerçek bir sorun varmış görüntüsü verir ama nedeni sadece talihsiz bir zamanlamadır. Zamanla ekip, o alarmın sesini susturmayı öğrenir ve susturulmuş bir alarmın haber vermediği ilk gerçek sorun, proje için haksız bir rota çizer. Bu kural, bunun ölüm fermanıdır.
- A) Bounded-retry koruması kalıcı kalsın (mevcut)
- B) Eski basit push'a dön (yarış kabul)
- C) Badge botu `'pull_request'` tetikine taşınsın, main'e hiç yazmasın
- D) Badge tamamen kaldırılsın

## Q110 — Köprü gelen-transfer ücret kesintisi (relayer fee) modeli
**Teknik:** ADIM5 Q9: inbound bridge transfer'larda relayer fee deduction implementasyonu — dışarıdan gelen varlıktan taşıyıcının payı işlem içinden kesiliyor, Q40 'zero-fee inbound' vaadiyle dengeleniyor. (8ba9779, bridge.rs)
**Non-teknik (herkes için):** Bir çek bozdurulurken vezneden 'elbette bozdurabilirsiniz ama bu işlemden şu ufak komisyonu keseriz' denmesi gibi: Budlum'a dışarıdan gelen bir varlığın içeri alınırken o varlığın içinden, taşımayı yapan aracının payı kesiliyor. Bu kesinti sayesinde taşıyıcı, kapıda çalışmaya devam eder; gelen de, kapıyı dış rüzgârda bırakılmaz. Bu modeli bırakıp sabit bir giriş ücretine dönülseydi herkes aynı bilet ücretini öderdi — bu, yeni gelenin 'bu sistem zenginleşmişlerin kulübü mü' sorusunu sormasına yol açar; tamamen ücretsiz yapılsa da taşıma hizmetinin maliyetini topluluk sırtlar ve o maliyet, yıllar içinde 'bu işin para ettiğini varsaymamıştık' diye anılan ilk hesap çatlağına dönüşürdü. Payın içinden kesilmesi, hem herkese kapıyı açmanın hem de işi yapanı yaşatmanın dengesidir.
- A) Gelen değerin içinden kesinti kalsın (mevcut, kullanıcı önden para aramaz)
- B) Sabit giriş ücreti (flat fee), içerikten bağımsız
- C) Tamamen ücretsiz inbound, fee relayer'a hazineden
- D) Fee uint oranı config-driven yapılsın, kod sabiti olmasın

## Q111 — Boost %80 payı: devnet-burn / mainnet-treasury davranış ayrımı (config-driven)
**Teknik:** NftBoost protocol_share %80: `burn_reserve_address=Some` ise treasury'ye, `None` (devnet_genesis) ise burn. Yani aynı kod iki ağda farklı ekonomi davranışı üretiyor; devnet testleri burn görür, mainnet treasury. (6dd66e5, genesis.rs:155)
**Non-teknik (herkes için):** Bir kasabanın iki farklı mahallesinde aynı meyve bahçesinden gelen kazancın, birinde doğrudan bağışa, diğerinde kasabanın ortak kasasına gitmesi gibi: Budlum'da öne çıkarma ücretlerinden ortaya çıkan büyük pay, deneme ortamında ziyan olurken gerçek ağda ortak kasaya taşınıyor — bu fark, tek programın içinde ayarla saklanıyor. Bu ayrımın iyi tarafı var: deneme ortamında kuruşlar yakılırken gerçek ortamda aynı paralar topluluğun fonu olur. Ama risk de var: ayar tek yerden okunacağı için gelecekte o ayar hangi rakamla yazıldı diye karışırsa — örneğin deneme ayarıyla gerçek ortam başlatılırsa — topluluğun kasasına akan paranın yıllarca 'görünmez olduğu' yaşanır ve bir gün bu sessizliği fark eden bir üye, 'kasanın tek kuruşu neden yok' diye sorduğunda cevap vermek çok zorlaşır. Ayar farkı teknik bir detay değil, yıllarca sürecek bir hazine güvenliği meselesidir.
- A) Config-driven ayrım kalsın (devnet burn, mainnet treasury, mevcut)
- B) Her iki ağda da treasury (devnet'te de treasury adres tanımla)
- C) Her iki ağda da burn (treasury tamamen kaldır)
- D) %80'in kaderini böl: yarısı burn yarısı treasury

## Q112 — Mempool politika parametreleri (RBF %10 / per-sender 100 / min fee 1)
**Teknik:** `MempoolConfig` default: `max_size=20000, max_per_sender=100, min_fee=1, rbf_bump_percent=10`; RBF replace `fee + fee*10/100` eşiği, `evict_lowest_fee` strict-greater, imza kontrolü pool'da YOK (validate_pool_transaction'da). (pool.rs:22-35,82-96,218)
**Non-teknik (herkes için):** Bir mahalle kahvesinde 'bir masada en fazla dört kişi olabilir, hesabı büyük müşteri küçük müşteriyi kovalar' kuralı gibi: Budlum'da da bir kişinin bekleme salonunda aynı anda en fazla yüz işi bekletebilir ve daha yüksek bedelli bir iş, düşük bedellinin yerini ancak belli bir farkla alabilir. Bu kurallar sayesinde hiçbir müşteri salonu terk edemez hale getiremez ve küçük işlerin her zaman bir şansı olur. Bu kurallar gevşerse biri elindeki binlerce ufak işle salonu doldurur ve diğerlerinin masası sürekli boşaltılır; sıkışırsa da her küçük değişiklik için masraf çıkar ve o çıkan masraf, sonunda platformun gerçek kullanıcılarına döner. Salon yönetimi, her kahve içene değil, kahve mekânın sürekliliğine yazılmalıdır — bu kural, o dengenin kalbi.
- A) Mevcut parametreler kalsın (20000/100/1/%10)
- B) Sıkılaştır: min fee yükselsin, per-sender düşsün (spam ağır)
- C) Gevşet: per-sender artsın (burst kullanımı)
- D) Parametreler config dosyasına taşınsın, hard-coded olmasın

## Q113 — Felaket alarm zinciri (kim/hangi kanal/kaç dakika)
**Teknik:** Runbook'larda fail-closed §4 var ama canlı felaket (zincir durması, HSM erişim kaybı, köprü takılması) için kişi-bazlı çağrı zinciri ve zaman bütçesi tanımlı değil. (operations/* eksik madde)
**Non-teknik (herkes için):** Bir site yöneticisinin 'su deposunda sızıntı olursa 15 dakika içinde şu üç oyuna haber ver, birine ulaşamazsan direkt şirketi ara' felaket rehberi gibi: Budlum'da bir felaket tespit edilirse kimin, hangi kanaldan, kaç dakika içinde harekete geçeceği önceden yazılmış. Bu rehberin en değerli olduğu an, herkesin en çok paniği yaşadığı andır: artık 'şaşırtıcı bir telefon' ile değil, önceden bilinen bir yoklamayla kurtarma başlar. Rehber olmazsa ilk gerçek felakette enerji, çözüme değil kime haber verileceğine harcanır; herkes birini arar, herkes başkasını bekler ve en kritik yarım saat 'ben değil sen ara' diyaloglarıyla geçer. Bir felakette yarım saatlik gecikme, haftalarca sürecek itibar kaybına dönüşebilir.
- A) On-call matrisi + 15dk ilk-yanıt SLA'sı runbook'a yazılsın
- B) STATUS_ONLINE kanalı yeterli (AI birliği gözetlemede)
- C) Sadece otomatik alarm (metrics alert), kişi ataması yok
- D) Mainnet sonrasına ertele

## Q114 — Restart replay-parity zorunluluğu (F4 replay-divergence)
**Teknik:** Boost dağıtım hook'ları yalnız produce (`blockchain.rs:2460-2462`) ve validate (`:2673-2675`) yollarında; `apply_block_effects`+`commit_block_durable` (restore/replay) hook'ları ÇALIŞTIRMIYOR → restart eden node'un `pending_bud_boost_share`/kredi bakiyesi canlı node'dan sapabilir. (STATUS_ONLINE ARENA3 bulgu)
**Non-teknik (herkes için):** Bir markette kasanın kapanıp tekrar açıldığında, bir müşterinin daha önceki alışverişlerini sıfırladığının anlaşılması gibi bir senaryonun önlenmesi: Budlum'u yeniden başlatan bir bilgisayar, kaldığı yerden ilerlerken toplamın canlı sistemle aynı şekilde güncellenmesi lazım. Bugün teşhis edilen ayrıntı şudur: bir yöntemle başlatılan bilgisayar, sonradan canlı ağdan gelen bakiye dağıtımlarını göremeyebiliyor ve bu, 'ayaküstü gelenin bildiği ile oturanın bildiği arasında para farkı' ilkesizliğine yol açıyor. Bu eşitleme yazılmazsa gelecekte bir bilgisayar başlangıçtan beri canlı çalışır, sonra yeniden başlatılır ve onun hesap defteri, odanın diğer ucundakiyle bir kuruş bile olsa ayrışır — ve bu kuruş, diğerleri için 'biz mi yanlışız o mu' tartışması başlatır. Yeniden başlatılanın bakiyesi ile hiç durmamış olanın bakiyesi asla ayrılmamalıdır; bu, paranın anayasası niteliğindedir.
- A) Hook'ları `apply_block_effects` içine taşı + replay-parity testi mühürle (replay==live assert)
- B) Divergence kabul edilir sayılsın, ilk canlı epoch'ta düzelir beklentisi
- C) Boost dağıtımı tamamen executor içine taşınsın (hook yok, tek yol)
- D) Dokümante et, düzeltmeyi mainnet sonrasına bırak

## Q115 — Zincir veri boyutu tavanı ve arşiv düğümü ayrımı
**Teknik:** Full node diski geçmişle büyür; prune (F1/Q-X1) içerik-silme içindir, zincir geçmişi arşiv politikası tanımsız. Arşiv node / pruned node ikiliği mainnet öncesi karar ister. (MAINNET_READINESS boşluğu)
**Non-teknik (herkes için):** Bir şehrin hem mahalle kütüphaneleri hem de merkez arşiv kütüphanesi olması — kitapların son yüzyılını hepsinde barındırması gibi: Budlum'da da her izleyenin tüm geçmişi mi taşıyacağı, yoksa 'arşiv görevlisi' tipi bilgisayarların mı bu yükü üstleneceği kararı gündemde. Tek tipte isteseydik, her ev kurulumunun devasa bir depo odası alması gerekecekti — bu, katılımı caydırır; arşiv ayrımı yapılırsa herkes aynı veriye ulaşabilir ama herkes onu taşımak zorunda kalmaz. Bu karar, 'hafızayı taşıma yükünü kimin sırtlacağını' belirler; ve bu yük haksız dağıtılırsa ileride 'fotoğraf arşivini sadece şirketler tutuyor, bireyler güvenemez' dünyasına döneriz. Ağın hafızası, yalnızca depolama sorunu değil, erişim adaleti sorunudur.
- A) Arşiv + pruned ikili tip: default pruned, arşiv gönüllü
- B) Tek tip: herkes tam geçmiş tutar (tavan yok)
- C) Tek tip: herkes pruned, arşiv merkezi servis
- D) Tavan config-driven, default beklemede

## Q116 — Devnet/testnet kullanıcı verisi mainnet'e taşınır mı (genesis seed)
**Teknik:** Devnet'te yaşayan NFT/SocialFi/BNS kayıtları gerçek ağ başlangıcına dahil edilirse ilk gün canlı içerik doğar; edilmezse temiz ama boş başlangıç. (MAINNET_GENESIS_CEREMONY karar boşluğu)
**Non-teknik (herkes için):** Bir yuvadan mezun olan bir çocuğun kardeşi için 'orada kalan oyuncaklarını da doğum gününde vermeyeceğiz, çünkü o artık yeni sınıfta' demek gibi: Budlum da deneme döneminde yaşayan kayıtların, gerçek ağa taşınıp taşınmayacağına karar verecek. Taşımayı seçmek, deneme günü yaratıcılarının emeğini görür ve kayıp hissettirmez; taşımamak, gerçek ağın 'denenmemiş' ve 'geçmişsiz' doğmasını sağlar. Bu kararın iki tarafında itibar var: birinde ilk günkü topluluk sesi duyulmamış hisseder, diğerinde yıllarca 'deneme kalıntısı' taşıyarak doğmuş bir geçmişin izleri silinmez. Her iki senaryoda da kaybeden aynı olmayacaktır; karar, hangi kaybın daha onarılabilir olduğu sorusuna dönüşmelidir.
- A) Taşınmasın: mainnet temiz doğar (deneme kalıntısı yok)
- B) Whitelist taşıma: doğrulanmış yaratıcıların içeriği seed edilir
- C) Tam taşıma: devnet state'i genesis'e gömülür
- D) Topluluk oylamasıyla karar verilsin

## Q117 — Harici audit firması seçim kriterleri (M7)
**Teknik:** Phase 0.43'te audit firması seçimi + kickoff var ama kriter/kapsam matrisi yok: kaç firma, hangi kapsam (kripto+consensus+ekonomi?), kim seçer. (PHASE0.42_PLAN boşluğu)
**Non-teknik (herkes için):** Bir sağlık raporu için iki farklı hastaneye görünmek gibi: Budlum'un gerçek ağa açılmadan önce, kodun içini ve güvenlik duruşunu dışarıdan bağımsız bir uzmanın denetlemesi kararı zaten alınmıştı; buradaki soru, o doktoru kimin seçeceği, kaç farklı doktorun bakacağı ve neye bakacağıdır. Tek doktorla yetinmek hızlıdır ve hesaplıdır ama o doktorun bilmediği bir bakış açısı olabilir; iki bakış, daha pahalıdır ama kör nokta şansını düşürür. Kararın sahipliği de önemlidir: 'onlar seçti' diyerek varamayacağımız bir güven vardır çünkü denetmenin kendisinin bağımsızlık kriterleri, belki de her şeyin üzerinde uzlaşılması gereken ilk meseledir. Çoğu proje o noktada 'ne olacak canım' der ve sonra yaşanan skandal, ilk toplantının hararetle konuşulmamış sorusunu tarihe gömer.
- A) Çift audit: biri kripto/konsensus, biri ekonomi/mantık; ekip önerir, kullanıcı onaylar
- B) Tek firma tam kapsam, teklif+röportajla seçim
- C) Bug bounty yeterli, formal audit ertele
- D) Kriter matrisi önce yazılsın, firma sonra

## Q118 — Açık kaynak lisans politikası
**Teknik:** Repo lisansı kararı mainnet öncesi netleşmeli: permissive (MIT/Apache-2.0), copyleft (GPL/AGPL) ya da karma (çekirdek permissive + uygulama copyleft). Bu karar ekosistem büyümesini ve ticari forku belirler. (repo kökünde lisans kararı boşluğu)
**Non-teknik (herkes için):** Bir marangozluk atölyesinin 'yaptığımız rafları isteyen istediği gibi kullanabilir ama adımızı vermek zorunda ve sattığında da bizden izin almalı' tabela kararı gibi: Budlum'un kodunun başka ellerde nasıl kullanılabileceği lisansı seçilmelidir. Kimisi tamamen serbest bırakır — başkaları üzerine büyük işler kurar ama kaynak zenginleştirmez; kimisi kısıtlar — kaynak zenginleşir ama topluluk eli cebinde kalır. Bu kararın iyi tarafı da kötü tarafı da uzun yıllar sürecek: bugün alınan lisans, yarın bu işin üzerine inşa edilecek şirketlerin, eğitim kurumlarının ve yarım dünya uzaktaki geliştiricinin hukuk kitabıdır. Tek cümlelik bir tabela, bir kültür doğurur veya öldürür; üzerinde iyi düşünülmelidir.
- A) Dual MIT+Apache-2.0 (maksimum benimseme)
- B) AGPL (ağ-kullanımı da kaynak zorunlu, ticari fork caydırıcı)
- C) Karma: consensus çekirdeği permissive, SocialFi/ekonomi copyleft
- D) Proprietary/source-available (BSL) ile başla, sonra aç

## Q119 — Genesis ceremony sonrası anahtar-kalıntı imha protokolü
**Teknik:** Ceremony'de üretilen genesis anahtarlarının ara kopyaları (RAM kalıntısı, geçici dosyalar, HSM dışı yedekler) için imha/doğrulama tutanağı tanımsız; tören hijyeni son adımı eksik. (MAINNET_GENESIS_CEREMONY 7.1 sonrası boşluk)
**Non-teknik (herkes için):** Bir düğünün ardından dağıtılan pasta cipslerinin paketlerinin 'yıl dönümünde tekrar kullanamayız diye imha tutanağı' gibi: Budlum'un açılış töreninde üretilen özel anahtarların imalat kalıntıları, törenin ardından ne yapılacağı belgelenmemiş durumdaydı — bu soru, o kalıntıların imhasını, saklanmasını ya da yetkisiz bir elden kurtarılmasını emrediyor. Bu kalıntılar, törenin en güvenli anında bile görünmez bir risktir; bugün zararsız gibi görünen kopya, yıllar sonra eldivensiz bir elin eline geçebilir. Ve her başarı, ilkelerinin arşivine gömülü yaşar: ileride 'açılış günü neler oldu' sorusunun cevabı yalnızca kutlamalardan değil, o kutlamanın tozu bile kontrol altına alındı mı sorusundan sorulur. Tören sonrası sessizliğin maliyeti, törenin kendisinden daha derine işler.
- A) İmha tutanağı + çoklu tanık imzası checklist'e eklensin
- B) Kalıntılar HSM escrow'a kilitlensin (imha yok)
- C) Hava-boşluklu (air-gapped) üretim imha gerektirmez sayılsın
- D) Tören dokümanına tek maddelik not yeterli

## Q120 — Mainnet ilk 30 gün: no-rollback ilkesi ve geri dönüş sınırı
**Teknik:** Zincir bir kez canlıya geçince tarihi geri sarma (rollback) prensip olarak yok; kritik hata yalnızca ileri-yönlü düzeltmeyle giderilir. Emergency halt (Q44) ile ilişki ve ilk 30 gün özel durumu tanımsız. (CONSTITUTION §7 + launch)
**Non-teknik (herkes için):** Bir uçak yolculuğunda 'acil iniş kararı kaptanın iki cümlesiyle verilir ve kimse bakmaz' ilkesinin tersine, Budlum'un ilk otuz gününde yaşanacak krizlerde 'dönüş yok, sadece içeriden iyileşme var' ilkesini belirleyen karar gibi: sistemin ilan edilen ilk saatlerinden sonra bir sorun çıktığında, geri dönüş mümkün müdür yoksa sadece ileri mi gidilir? Şimdiden söylenen ilke ilktür: yaşanacak hiçbir sorun için tarihi silip yeniden başlama yolu yoktur; yalnızca içeriden düzeltilen ve öğrenilen bir sistem yaşar. Bu ilke, topluluğa tek mesaj verir: burada geçmiş kutsaldır, hatalar ders olur ama asla silinmez. Bu, hem cesaret hem de sorumluluk konuşmaktır; gelecekteki her krizde eldeki tek pusula bu prensiptir ve bu pusulayı bugünden herkesle paylaşmak, ileride kriz gecesi 'onlar da mı bizim gibi bilmiyordu' diye tartışmaya yer bırakmaz.
- A) No-rollback mutlak: hata ileri düzeltilir, tarih kutsal (ilke beyanı docs'a)
- B) İlk 30 gün istisna: tek genesis-yeniden-doğuş hakkı saklı
- C) Emergency halt sonrası rollback mümkün (halting = zaman dondurma)
- D) Karar topluluk referandumuna bırakılsın

---

**Son not:** Bu anketteki her madde için cevap anahtarını (A/B/C/D/E) işaretleyip yollayın, kalan teknik borçlar `docs/STATUS_ONLINE.md` ve `docs/PHASE9_FINAL_DENETIM_ARENA3.md` üzerinden kapatılacak. Force-push yasak, CI yeşili olmadan Phase 10'a geçilmez.

**Genişletme kaydı (ARENA3, 2026-07-17):** Orijinal 100 sorunun gövdeleri (başlık + teknik + seçenekler) BİREBİR korundu — diff kanıtı: kaldırılan 102 satır = 100 kısa non-teknik satır + başlık + amaç satırı, başka hiçbir şey. Tüm "Non-teknik (herkes için)" açıklamalar uzun, teknik-kelimesiz ve sonuç-odaklı yeniden yazıldı (oturtulan anlatım tarzı: günlük hayat analojisi + Budlum'un yaşayabileceği somut sonuçlar). Q101-Q120 eklendi: dependabot/bağımlılık göçü, köprü geri-dönüş eşleştirmesi (correlation), storage-prune tetikleyicisi, restart replay-parity, arşiv düğümü ayrımı, devnet→mainnet taşınması, lisans, ceremony kalıntı imhası, no-rollback ilkesi vb. — mevcut 100 sorunun kapsamadığı gerçek boşluklar. Üretim tekrarlanabilir: `scripts/anket_expand_apply.py` + `anket_expand_p1.py` + `anket_expand_p2.py`.

Co-authored-by: ARENA2 <arena2@budlum.ai>
Co-authored-by: ARENA3 <arena3@budlum.xyz>
