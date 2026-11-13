# Bulgu B-0005

## Kimlik

B-0005

## Konum

`crates/wallet-core/src/bns.rs`, `verify_bns_recipient_proof` imzasi

```rust
pub fn verify_bns_recipient_proof(
    requested_name: &str,
    claimed_target: &[u8; 32],
    proof: &WalletBnsProof,
    expected_bns_root: &[u8; 32],   // cagiran veriyor
    current_epoch: u64,             // cagiran veriyor
) -> Result<[u8; 32], String>
```

## Onem

Yuksek. Strix kaydi `S-126-4568600764` bunun uzerine yazildi.

## Ne yanlis

Fonksiyon koku ve epoch'u olagan arguman olarak aliyor. `wallet-core` icinde
baslik tipi yok, baslik istegi yok, baslik dogrulamasi yok. Crate'in modelledigi
tek kok ve epoch kanali `bud_bnsGetProof` yanitinin kendisi.

## Neden yanlis

Kanit koke gore dogrulanir. Kok yanitla gelirse yanit kendi kendini dogrular.
Yalan soyleyen bir dugum kendi urettigi koku, o koke uyan dali ve o dalin
epoch'unu tek cevapta gonderir. Uc kontrol de gecer.

## Neye yol acar

- Kullanici `.bud` adi yazar, cuzdan saldirganin adresini imzalar.
- Ekranda dogru ad gorunur. Alici yanlistir.
- Ekran guveni bosa gider: kullanici adi dogru gordugu icin odemeyi onaylar.

## Nasil duzeltilir

Iki parca gerekir.

1. **Baslik kaynagi.** `wallet-core` bir hafif istemci tutmali: baslik
   istegi, baslik ozeti ve state root cikarimi. Ag gecidinin
   `web_gateway::resolve::StateRoots` trait'i bu isin sekli; cuzdan tarafinda
   ayni sozlesme gerekir.
2. **API'yi daralt.** Fonksiyon koku ve epoch'u parametre olarak almamali.
   Dogrulanmis bir basliktan okumali. Boylece "cagiran dogru koku verdi"
   varsayimi ortadan kalkar.

Ara adim olarak: fonksiyonun belgesine su cumle yazilir. "`expected_bns_root`
ve `current_epoch` basliktan gelmelidir. Bu crate baslik dogrulamasi sunmaz;
cagiran sunmakla yukumludur." Bu bir duzeltme degil, bir uyaridir. Asil
duzeltme baslik istemcisidir.

## Durum

acik. Tasarim var, kod yok.

Neden simdi kodlanmadi:

- Dogru duzeltme `wallet-core` icin bir baslik istemcisi demek. Bu, `rpc.rs`
  yuzeyini, ag katmanini ve `BnsRecipient` akisini birlikte degistirir.
- Yigin uzerinde `rpc` ve `chain` su anda hareketli. `bd1e6a79` ayni dosyalara
  dokundu.
- Yanlis bir baslik istemcisi, baslik istemcisi olmamasindan daha kotudur:
  kullaniciya dogrulanmis hissi verir.

Onerilen sira, `audit-notes/testnet/ip-11.md` (mobil cekirdek ve hafif istemci)
maddesi icinde:

1. `wallet-core` icinde `HeaderSource` trait'i: `latest_height()` ve
   `state_root_at(height) -> Option<[u8; 32]>`.
2. `verify_bns_recipient_proof_from_header(source, ...)` fonksiyonu. Eski
   fonksiyon `#[deprecated]` olur, silinmez.
3. Bir test: dugum kendi urettigi koku verir, cuzdan reddeder.


## Tur 2: kod indi

`crates/wallet-core/src/bns.rs`:

- `HeaderSource` trait: `bns_root_at(height) -> Option<([u8; 32], u64)>`.
  Cuzdan guvendigi bir kaynak verir; kok ve epoch oradan okunur.
- `verify_bns_recipient_proof_from_header`: kok ve epoch'u `headers`ten alip
  `verify_bns_recipient_proof`'a veriyor. Cozum yolu bu.
- `HeaderUnknown(u64)`: basligi olmayan yukseklik icin ayri tip, cagiran
  "dugum yalan soyledi" ile "ben gerideyim"i ayirt edebilsin.
- `WalletBnsProof.header_height`: capanin ihtiyac duydugu alan.

Uc test:

- `a_proof_verifies_against_the_root_of_the_header_the_wallet_holds`
- `a_root_chosen_by_the_node_cannot_substitute_a_recipient` - dugumun kendi
  urettigi kayit, dugumun kendi kokuyle dogrulanir; cuzdanin basligindaki
  kokle reddedilir. Ayni sahtelik `expected_bns_root` cagirandan gelince
  gecer; kapatilan kusur tam olarak bu.
- `a_proof_for_a_height_the_wallet_has_no_header_for_is_refused`

Eski `verify_bns_recipient_proof` silinmedi. Uc test ve tek cagiran hala onu
kullaniyor; yeni giris noktasi yaninda duruyor. Cagiranlari tasiyip eski
fonksiyonu `#[deprecated]` yapmak sirada.

## Yerel kanit

`wallet-core` bu makinede derleniyor (1.9 GB'in altinda kaliyor):

- `cargo fmt --all --check` temiz
- `cargo clippy --lib --all-features -- -D warnings` temiz
- `cargo test --lib` 163 gecti, 0 basarisiz

Commit `026711ba`. CI kosusu yok; kuyruk PR #163'te bekliyor.
