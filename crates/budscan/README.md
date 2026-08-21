# Budscan

Budlum'un merkeziyetsiz tarayicisi. Web3 uzantilarini ve merkeziyetsiz
depolamayi acar; cuzdan adresleri, NFT'ler ve siteler ayni kutudan aratilir.

```
budscan/
  src/          tarayici cekirdegi (Rust, kendi workspace'i)
  browser/      Gecko yama katmani (yamalar + ayarlar + yerellestirme)
```

## Ne yapar

Kullanici adres cubuguna `ayaz.bud` yazar:

1. **Siniflandirma** (`query.rs`) - yazilan sey ad mi, adres mi, NFT mi, sema mi.
2. **Ad kurali** (`name_rule.rs`) - gecmeyen ad acilmaz, sebebi soylenir.
3. **Cozum** - `.bud` ise BNS'ten (`bns_proof.rs`), `.eth` ise ENS'ten (`ens.rs`).
4. **Getirme** (`fetch.rs`) - dort getirici, her biri kendi gucunu beyan eder.
5. **Dogrulama** - getirilen baytlarin istenen baytlar oldugu **olculur**.
6. **Rozet** (`resolve.rs`) - en zayif halka adres cubugunda gosterilir.

Besinci adim bu tarayicinin var olma sebebi. Bugunku web'de tarayici,
sunucunun gonderdigi baytlarin dogru baytlar oldugunu bilmez: TLS yalniz
**kimin** gonderdigini soyler, **neyin** gonderildigini degil. Icerik adresli
bir agda `manifest_id` baytlarin hash'idir, yani dogrulama bir
karsilastirmadir ve tarayicinin kime guvenecegine karar vermesi gerekmez.

## Dogrulama gucu: dort deger

| deger | ne demek | ornek |
|---|---|---|
| `dogrulandi` | baytlarin ozeti beklenen kimlige esit | B.U.D. manifest, IPFS raw CID, Arweave `data_root` |
| `yalniz tasima` | TLS var, icerik dogrulanmadi | siradan HTTPS |
| `yalniz beyan` | bir dugum cevap verdi, kanit dogrulanmadi | kanitsiz BNS cozumu |
| `reddedildi` | olculdu ve tutmadi; icerik gosterilmez | hash uyusmazligi, ad kurali reddi |

Rozet **en zayif halkayi** gosterir. Baytlari hash'iyle tutan bir sayfa,
cozumu kanitsizsa `yalniz beyan` der: baytlar kendileriyle tutarli ve
kimse onlarin bu isme ait oldugunu kanitlamadi.

Dogrulanamayan icerik **yasaklanmiyor, etiketleniyor**. Yasaklamak tarayiciyi
kullanilmaz yapar ve kullaniciyi hic dogrulama yapmayan baska bir tarayiciya
gonderir. `reddedildi` bunun istisnasi: orada olcum yapildi ve tutmadi.

## Neyin dogrulanmadigi da yazili

Bu crate'in bir kismi **yapilamayanin** kaydidir. Hicbiri sessizce
`dogrulandi` diye etiketlenmiyor:

* **BNS cozumu bugun isim basina kanitlanamiyor.** `BnsRegistry::root()`
  (`src/bns/registry.rs:299`) butun kayit defterini tek bir SHA-256 akisina
  yaziyor, Merkle agacina degil. Tek isim icin kanit uretecek yapi yok;
  `AccountState::calculate_state_root` onu `bns_v1` etiketiyle state root'a
  katiyor ve dogrulamak defterin tamamini gerektiriyor. Kanit bicimi
  degistirmek bir **konsensus yuzeyi degisikligi** ve bu tarayicinin tek
  tarafli alacagi karar degil (`bns_proof.rs`).
* **Baslik kesinligi tarayicida dogrulanmiyor.** Yedi
  `DomainFinalityAdapter` bicimi var (PoW header-chain, PoS, PoA, BFT, ZK,
  depolama attestasyonu, AI cikarimi) ve hicbiri istemci tarafinda
  uygulanmadi (`light_client.rs`).
* **IPFS `dag-pb` coklu blok icerik dogrulanmiyor.** UnixFS DAG yurumek
  ayri bir is; `CidVerdict::UnsupportedMultiblock` bunu soyluyor (`cid.rs`).
* **IPNS ve Swarm icin getirici yok.** HTTPS'e dusurmek, dogrulanmamis
  icerigi dogrulanmis gibi gostermek olurdu (`resolve.rs`).
* **Sifreli icerikte anahtar dagitimi cozulmedi.**
  `ContentEncryption::ClientSide` var; anahtarin tarayiciya nasil geldigi
  erisim-izni katmaninin isi ve burada yok.
* **Sanal alan siniri olculmedi.** Dogrulanmis icerik guvenli icerik degildir;
  hash'i tutan bir sayfa da kotu niyetli olabilir. Gecko'nun sanal alani bu
  isi yapiyor ve yamalarin onu zayiflatmadiginin nasil gosterilecegi
  olculmedi.

## Kabuk yok

Yama araclari da dahil hicbir sey kabuk degil. Sebep olculdu: yanlis yazilmis
bir degisken kabukta hata degil bos dizgidir, yani bir kontrol hicbir seyi
inceleyip OK diyebilir. Somut ornek `browser/README.md` icinde.

`patchset.rs`'de "hicbir sey inceleyemedim" ayri bir sonuc
(`Verdict::Vacuous`) ve `is_ok()` false doner.

## Kopyalar ve onlari tutan kapi

Budscan `budlum-core`'a **baglanmiyor**: baglansa libp2p, tokio, jsonrpsee ve
sled'i de baglardi ve bir tarayicinin guven sinirinda o grafik istenmez.
Bedeli iki kopya, ve bedel olculuyor:

| kopya | tarayici | zincir |
|---|---|---|
| ad kurali | `src/name_rule.rs` | `xtask/gates/.../bns_names_are_safe_in_an_address_bar.rs` |
| `ContentId` | `src/content_id.rs` | `src/storage/content_id.rs` |
| boyut siniri | `src/fetch.rs` | `src/gateway/service.rs` |
| `EPOCH_LENGTH` | `src/light_client.rs` | `src/chain/blockchain.rs` |

`budscan-name-rule-parity` kapisi dordunu de CI'da olcuyor. Ayrisma sessiz
olurdu: tarayici bir adi kabul eder zincir etmez, ya da tarayici bir baytin
dogrulandigini soyler zincir baska bir kimlik hesaplar.

## Belge ile olcum arasindaki fark

Mimari notu: `аyaz.bud` (ilk harf Kiril
U+0430) icin `xn--yaz-hlc.bud` yaziyor. **Yanlis.** RFC 3492 algoritmasi ve
Python'un `str.encode("idna")` referansi ikisi de `xn--yaz-5cd.bud`
uretiyor. Kod hesaplanan degeri tasiyor, belgeden kopyalanani degil
(`punycode.rs`, `one_cyrillic_letter_in_a_latin_word` testi).

## Calistirma

```
cargo test  --manifest-path budscan/Cargo.toml
cargo clippy --manifest-path budscan/Cargo.toml --all-targets -- -D warnings
cargo run   --manifest-path budscan/Cargo.toml --bin budscan -- kendini-sina
cargo run   --manifest-path budscan/Cargo.toml --bin budscan -- siniflandir ayaz.bud
cargo run   --manifest-path budscan/Cargo.toml --bin budscan -- ad-kurali "javascript:alert(1)"

cargo run --release --manifest-path xtask/gates/Cargo.toml -- budscan-name-rule-parity
cargo run --release --manifest-path xtask/gates/Cargo.toml -- budscan-patchset
```

107 test, hepsi gecer. `browser/` altinda motor kaynagi yok ve olmayacak:
yapim sirasinda indirilir, yamalar uygulanir, sonuc derlenir.
