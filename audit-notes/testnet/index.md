# Testnet maddeleri

Bu dosya `audit-notes/testnet/index.md`. Kaynak: `THE_BUDLUM_DIREKTIF` bolum 15.7 bagimlilik tablosu, canli olarak okundu.

Onemli not: `THE_BUDLUM_DIREKTIF` dosyasi depoda yok. Arandi (`git ls-tree -r --name-only origin/main` ve `origin/testnet`), iki dalda da bulunamadi. Bu yuzden kaynak olarak kullanicinin verdigi dosya kullanildi: `uploads/THE_BUDLUM_DIREKTIF (1) (1).md`, 6044 satir. Dosya depoya eklenmedi; direktif dosyalari commit edilmez.

Toplam 64 is paketi. 47 paket TLG engelli, 17 paket TLG sonrasi.

Is paketi kimligi depoda ve GitHub'da `WP-NN`, bu belgede `IP-NN`. Ayni pakettir.

## Durum degerleri

- `yok`: depoda karsiligi yok
- `kismi`: bir bolumu var, tamami yok
- `var`: tamami var
- `dogrulandi`: var ve canli olarak kosuldu

## Paketler

| İP | Başlık | Şerit | Katman | TLG | Bağımlılık | Taş | Depo durumu | Tasarım |
|---|---|---|---|---|---|---|---|---|
| İP-01 | Canlı doğrulama: çekirdek | A | T-Açılış | Evet | Yok | M0 | yok | [ip-01.md](ip-01.md) |
| İP-02 | Canlı doğrulama: depolama | B | T-Açılış | Evet | Yok | M0 | yok | [ip-02.md](ip-02.md) |
| İP-03 | Canlı doğrulama: yürütme, BudZero, domainler, gizlilik, AI | C | T-Açılış | Evet | Yok | M0 | yok | [ip-03.md](ip-03.md) |
| İP-04 | Canlı doğrulama: istemciler, işletim, CI, belgeler ve birleşik durum | D | T-Açılış | Evet | Yok | M0 | yok | [ip-04.md](ip-04.md) |
| İP-05 | Kavram adı haritası ve sayaç kapısı | D | T-Açılış | Evet | İP-04 | M1 | yok | [ip-05.md](ip-05.md) |
| İP-06 | Kalıcılık ve durum kurtarma taşıması | B | T-Açılış | Evet | İP-02 | M1 | yok | [ip-06.md](ip-06.md) |
| İP-07 | Eski depolama sistemlerinin kaldırılması | B | T-Açılış | Evet | İP-06 | M1 | yok | [ip-07.md](ip-07.md) |
| İP-08 | Doğrulayıcı sınıfları ve tek kayıt | A | T-Açılış | Evet | İP-01 | M1 | yok | [ip-08.md](ip-08.md) |
| İP-09 | Yürütme ortamı arayüzü | C | T-Açılış | Evet | İP-03 | M1 | yok | [ip-09.md](ip-09.md) |
| İP-10 | B.U.D. 3.0 iskeleti ve ortak tipler | B | T-Açılış | Evet | İP-07 | M2 | yok | [ip-10.md](ip-10.md) |
| İP-11 | Mobil çekirdek ve hafif istemci | D | T-Açılış | Evet | İP-10, İP-12, İP-13, İP-15, İP-20 | M4 | yok | [ip-11.md](ip-11.md) |
| İP-12 | Kurul tabanlı kesinlik, Anında Koltuk Devri, konsensüs sertleştirme | A | T-Açılış | Evet | İP-08 | M2 | yok | [ip-12.md](ip-12.md) |
| İP-13 | Varlık protokolü ve askıya alma | A | T-Açılış | Evet | İP-12 | M3 | yok | [ip-13.md](ip-13.md) |
| İP-14 | Anında Görev Devri ve felaket kipi | A | T-Açılış | Evet | İP-12, İP-13, İP-20, İP-21 | M4 | yok | [ip-14.md](ip-14.md) |
| İP-15 | Ağ: NAT geçişi ve P2P sertleştirme | A | T-Açılış | Evet | İP-01 | M2 | yok | [ip-15.md](ip-15.md) |
| İP-16 | Genesis, tören aracı ve ekonomi | A | T-Açılış | Evet | İP-08 | M3 | yok | [ip-16.md](ip-16.md) |
| İP-17 | Durum geçişi ve zincir sertleştirme | A | T-Açılış | Evet | İP-01, İP-06 | M2 | yok | [ip-17.md](ip-17.md) |
| İP-18 | Segmentasyon ve RFC 6330 fountain kodu | B | T-Açılış | Evet | İP-10 | M3 | yok | [ip-18.md](ip-18.md) |
| İP-19 | BOF-1 nesne biçimi, QR sunumu ve video taahhüdü | B | T-Açılış | Evet | İP-10, İP-24 | M3 | yok | [ip-19.md](ip-19.md) |
| İP-20 | Sınıf duyarlı yerleşim, saklama kanıtı ve onarım | B | T-Açılış | Evet | İP-08, İP-18 | M3 | yok | [ip-20.md](ip-20.md) |
| İP-21 | Yükleme, görüntüleme, `StorageTx` v3 ve RPC | B | T-Açılış | Evet | İP-18, İP-19, İP-20 | M3 | yok | [ip-21.md](ip-21.md) |
| İP-22 | Tekilleştirme, başvuru, silme, mühürlü içerik ve izinler | B | T-Açılış | Evet | İP-21 | M3 | yok | [ip-22.md](ip-22.md) |
| İP-23 | Bağımlı modüllerin B.U.D. 3.0 geçişi | B | T-Açılış | Evet | İP-22 | M4 | yok | [ip-23.md](ip-23.md) |
| İP-24 | A0 kodek kayıt defteri ve erişim katmanı | B | T-Açılış | Evet | İP-10 | M3 | yok | [ip-24.md](ip-24.md) |
| İP-25 | Depolama ücreti, Saklama Vakfı ve saklama ödülleri | B | T-Açılış | Evet | İP-16, İP-21 | M4 | yok | [ip-25.md](ip-25.md) |
| İP-26 | Yürütme Koordinatörü ve EE işçileri | C | T-Açılış | Evet | İP-07, İP-09 | M2 | yok | [ip-26.md](ip-26.md) |
| İP-27 | EVM yürütme ortamı ve yabancı zarf | C | T-Açılış | Evet | İP-26 | M3 | yok | [ip-27.md](ip-27.md) |
| İP-28 | Ethereum JSON-RPC ağ geçidi | C | T-Açılış | Evet | İP-27 | M4 | yok | [ip-28.md](ip-28.md) |
| İP-29 | WASM (CosmWasm ABI) ve Cosmos RPC alt kümesi | C | T-Açılış | Evet | İP-26 | M3 | yok | [ip-29.md](ip-29.md) |
| İP-30 | Evrensel Çağrı ve Evrensel Varlık Kaydı | C | T-Açılış | Evet | İP-27, İP-29 | M4 | yok | [ip-30.md](ip-30.md) |
| İP-31 | SVM ve Solana RPC alt kümesi | C | T-Açılış | Evet | İP-26 | M4 | yok | [ip-31.md](ip-31.md) |
| İP-32 | Move (Aptos) ve Aptos REST alt kümesi | C | T-Açılış | Evet | İP-26 | M4 | yok | [ip-32.md](ip-32.md) |
| İP-33 | BudZero yürütme ortamı ve BudZero sağlamlık | C | T-Açılış | Evet | İP-26 | M3 | yok | [ip-33.md](ip-33.md) |
| İP-34 | Göç Kiti | C | T-Açılış | Hayır (Beta) | İP-28 | Koşul değil | yok | [ip-34.md](ip-34.md) |
| İP-35 | Uygunluk, gaz kalibrasyonu ve çapraz mimari | C | T-Açılış | Evet | İP-27, İP-29, İP-31, İP-32, İP-33 | M4 | yok | [ip-35.md](ip-35.md) |
| İP-36 | Android doğrulayıcı uygulaması | D | T-Açılış | Evet | İP-11 | M4 | yok | [ip-36.md](ip-36.md) |
| İP-37 | Mobil cihaz matrisi ve saha testi | D | T-Açılış | Evet | İP-36 | M4 | yok | [ip-37.md](ip-37.md) |
| İP-38 | iOS fırsatçı uygulaması | D | T-Açılış | Hayır (Beta) | İP-11 | Koşul değil | yok | [ip-38.md](ip-38.md) |
| İP-39 | Cüzdan çekirdeği ve CLI | D | T-Açılış | Evet | İP-08, İP-21, İP-27 | M4 | yok | [ip-39.md](ip-39.md) |
| İP-40 | Gezgin ve dizinleyici | D | T-Açılış | Evet | İP-21, İP-26 | M4 | yok | [ip-40.md](ip-40.md) |
| İP-41 | Musluk ve işletim | D | T-Açılış | Evet | İP-16 | M4 | yok | [ip-41.md](ip-41.md) |
| İP-42 | CI, kapılar ve tedarik zinciri | D | T-Açılış | Evet | İP-04 | M2 | yok | [ip-42.md](ip-42.md) |
| İP-43 | Belgeler, README ve TLG raporu | D | T-Açılış | Evet | İP-46, İP-47, İP-48 | M6 | yok | [ip-43.md](ip-43.md) |
| İP-44 | Domainler, köprü, uzlaşma ve sözleşmeler | A | T-Açılış | Evet | İP-01 | M4 | yok | [ip-44.md](ip-44.md) |
| İP-45 | Gizlilik, AI ve hesap soyutlama: testnet sınırı | B | T-Açılış | Evet | İP-22 | M4 | yok | [ip-45.md](ip-45.md) |
| İP-46 | Tören provası, prova ağı ve ölçümler | D | T-Açılış | Evet | M4 | M5 | yok | [ip-46.md](ip-46.md) |
| İP-47 | Bağımsız inceleme 1: çekirdek ve depolama | Çapraz (C veya D) | T-Açılış | Evet | M4 | M5 | yok | [ip-47.md](ip-47.md) |
| İP-48 | Bağımsız inceleme 2: yürütme, mobil ve istemciler | Çapraz (A veya B) | T-Açılış | Evet | M4 | M5 | yok | [ip-48.md](ip-48.md) |
| İP-49 | Evrensel Nesne Katmanı | A | T-Genişleme | Hayır | M7, İP-30, İP-44 |  | yok | [ip-49.md](ip-49.md) |
| İP-50 | Move (Sui lehçesi) yürütme ortamı | C | T-Genişleme | Hayır | İP-35 |  | yok | [ip-50.md](ip-50.md) |
| İP-51 | Cairo yürütme ortamı | C | T-Genişleme | Hayır | İP-35 |  | yok | [ip-51.md](ip-51.md) |
| İP-52 | SVM ve Move işaretçileri | C | T-Genişleme | Hayır | İP-30, İP-31, İP-32 |  | yok | [ip-52.md](ip-52.md) |
| İP-53 | NEAR WASM, PolkaVM, TVM, UTXO betiği, Plutus | C | T-Genişleme | Hayır | İP-35 |  | yok | [ip-53.md](ip-53.md) |
| İP-54 | Paylaşılan sıkıştırma bağlamı, ek kodekler, gizli tekilleştirme | B | T-Genişleme | Hayır | İP-22, İP-24 (gizli tekilleştirme kısmı ayrıca İP-56) |  | yok | [ip-54.md](ip-54.md) |
| İP-55 | Canlı yayın | B | T-Genişleme | Hayır | İP-21 |  | yok | [ip-55.md](ip-55.md) |
| İP-56 | BudZero gizlilik çekirdeği, yüklem kanıtları, rıza ve PTP-1 | B | T-Genişleme | Hayır | İP-22, İP-33 |  | yok | [ip-56.md](ip-56.md) |
| İP-57 | AI Doğrulama Katmanı | A | T-Genişleme | Hayır | İP-45, İP-56 |  | yok | [ip-57.md](ip-57.md) |
| İP-58 | F-Droid ve yeniden üretilebilir Android derlemesi | D | T-Genişleme | Hayır | İP-36 |  | yok | [ip-58.md](ip-58.md) |
| İP-59 | Paralel yürütme | C | T-Genişleme | Hayır | İP-35 |  | yok | [ip-59.md](ip-59.md) |
| İP-60 | BudZero özyineleme, RV32, ön derlemeler, domain kesinlik kanıtı, blok toplu kanıtı | C | T-Genişleme | Hayır | İP-56 |  | yok | [ip-60.md](ip-60.md) |
| İP-61 | RPC ve kriptografi sertleştirme | D | T-Açılış | Evet | İP-01 | M2 | yok | [ip-61.md](ip-61.md) |
| İP-62 | Evrensel Nesne Katmanı: CosmWasm ve Cosmos SDK ailesi | A | T-Genişleme | Hayır | İP-49, İP-29 |  | yok | [ip-62.md](ip-62.md) |
| İP-63 | Evrensel Nesne Katmanı: SVM ailesi | A | T-Genişleme | Hayır | İP-49, İP-31 |  | yok | [ip-63.md](ip-63.md) |
| İP-64 | Evrensel Nesne Katmanı: Move ailesi | A | T-Genişleme | Hayır | İP-49, İP-32 |  | yok | [ip-64.md](ip-64.md) |

## Alti is paketi disinda kalan is

Direktifin 18. bolumu testnet acilis kapisini (TLG) tanimlar. TLG engelli 47 paket bitmeden kapi gecilmez.

## Ilk tur

Ilk turda T-Acilis katmanindaki M0 tasi ele alinir: IP-01, IP-02, IP-03, IP-04. Bunlar canli dogrulama paketleridir ve digerlerinin bagimliligidir. Her biri bir alani bastan sona kosar ve bulunan her hatayi bulgu olarak yazar.

