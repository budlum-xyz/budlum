# B-0009 - A wallet-core test has been red on its own

Durum: cozuldu
Asama: 8 (`crates/wallet-core`)
Onem: orta

## Kusur

`crates/wallet-core/src/lib.rs` icindeki
`d2_wallet_rejects_forged_spend_secret_and_bad_blindings` cuzdani 16 bayt
entropi ile kuruyor ve sonucu `unwrap()` ediyor:

```rust
let mut w = Wallet::from_entropy(&[0x67u8; 16]).unwrap();
```

`Wallet::from_entropy` 32 bayt istiyor (`lib.rs:1172`) ve 16 bayti
`InvalidEntropy(16)` ile reddediyor. Ayni crate'te uc test bu reddi bilerek
dogruluyor: `generate_12_word_wallet_is_refused`, `from_entropy_valid_sizes`,
`entropy_size_preserves_mnemonic_word_count`. Yani test, tasarimca yasak olan
bir seyi yapiyor ve kendi kendine panikliyor.

Sonuc: `cargo test --lib` bu crate'te kirmizi. `production` feature'i ile de
kirmizi. Test, cuzdanin 16 bayt kabul ettigi eski bir surumden kalmis.

## Onemi

Bu bir guvenlik acigi degil, ama testnette onemli: crate'in test paketi
kirmizi oldugu surece hicbir yesil CI bu crate hakkinda bir sey soylemiyor.
Kirmizi bir test, yeni bir gercek kirmiziligi gizler.

## Duzeltme

Entropi 32 bayta cikarildi ve gerekce yazildi. Test, altindaki ozel transfer
redlerini sinamak icin var; entropi boyutu onun konusu degil, ve 16 bayt
tasarimca reddediliyor.

```rust
// 32 bytes: this test is about the private-transfer refusals below,
// not about entropy size, and a 16-byte seed is refused by design
// (`generate_12_word_wallet_is_refused`).
let mut w = Wallet::from_entropy(&[0x67u8; 32]).unwrap();
```

Mantik zayiklatilmadi: 16 bayt hala reddediliyor, o davranisi dogrulayan uc
test yerinde.

## Kanit

Commit `026711ba`. Yerel, `crates/wallet-core` icinde:

- `cargo test --lib` 163 gecti, 0 basarisiz
- `cargo clippy --lib --all-features -- -D warnings` temiz
- `cargo fmt --all --check` temiz

CI kosusu yok. Kuyruk PR #163'te bekliyor. Yerel kanit tek basina sayilmaz;
bu bulgu CI yesil olana kadar "yerelde dogrulandi" olarak okunur.
