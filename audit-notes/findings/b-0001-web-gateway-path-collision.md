# Bulgu B-0001

## Kimlik

B-0001

## Konum

`src/gateway/mod.rs`, `src/lib.rs:32`

B14 maddesi ag gecidini `src/gateway/` altina koydu:

```
src/gateway/mod.rs
src/gateway/host.rs
src/gateway/manifest.rs
src/gateway/policy.rs
src/gateway/resolve.rs
```

`main` dalinda ayni yol zaten dolu:

```
$ git ls-tree -r --name-only origin/main -- src/gateway/
src/gateway/atlas.rs
src/gateway/mod.rs
src/gateway/passport.rs
src/gateway/service.rs
```

`main` dalindaki `src/gateway/mod.rs` ilk satiri:

```rust
pub mod atlas;
pub mod passport;
pub mod service;
```

## Onem

Yuksek

## Ne yanlis

Iki farkli sey ayni modul yolunu istiyor. `main` dalindaki `gateway` bir cuzdan
gecididir: atlas, passport ve service. B14'un istedigi `gateway` bir web ag
gecididir: host ayristirma, site manifesti, yanit ilkesi ve kanit cozumleme.

`testnet` dali `main` dalinin torunudur. Bu iki dal birlestiginde `src/gateway/`
altinda iki kume dosya ayni `mod.rs` icin yarisir. `mod.rs` tek bir dosyadir, bu
yuzden birlesme ya bir tarafi siler ya da `lib.rs` icinde `pub mod gateway;`
satirini iki kez uretir.

## Neden yanlis

Modul yolu bir ad alanidir. Ayni yolu iki farkli sorumluluk icin kullanmak, iki
ekibin ayni dosya adini kullanmasi gibidir: birlestirme sirasinda hangi
`mod.rs` kaldiginin bir kurali yoktur ve kaybeden taraf sessizce kaybolur.
Kaybolan taraf burada bir butun yetenektir, tek bir fonksiyon degil.

## Neye yol acar

- Birlestirme cakismasi. `main` hedefli PR yigini ilerlediginde `src/gateway/`
  icin cakisma cikar.
- Sessiz kayip. Cakisma elle cozulurse B14 modulu ya da cuzdan gecidi
  kaybolur; ikisi de derleme hatasi vermez, sadece bir daha cagrilmaz.
- Cift tanim. `pub mod gateway;` iki kez yazilirsa derleme hatasi verir, ama bu
  hatayi gormek icin birinin bu dali `main` ile birlestirmesi gerekir.

## Nasil duzeltilir

1. Yeni modulu `src/gateway/` yolundan cikar.
2. `git mv src/gateway src/web_gateway`.
3. `src/lib.rs` icinde `pub mod gateway;` satirini `pub mod web_gateway;`
   yap. `main` dalindaki `pub mod gateway;` satiri yerinde kalir.
4. Modul icindeki `crate::gateway::` yollarini `crate::web_gateway::` yap.
5. `xtask/gates/src/gates/gateway_gate.rs` icindeki adli test yollarini
   `web_gateway::` onekiyle guncelle.
6. `src/bns/README.md` icindeki yolu guncelle ve neden `web_gateway`
   oldugunu bir cumleyle yaz.
7. `cargo fmt --all --check` calistir.

## Durum

cozuldu

- Commit: `8b5592af`
- CI run: yok. Kuyruk tikali, yesil kosu bekliyor.
