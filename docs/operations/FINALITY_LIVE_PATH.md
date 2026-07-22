# Finality Live-Path Son Taraması (Task 2 §1.3)

**Tarih:** 2026-07-15
**Durum:** Kod kapsamı eklendi; CI doğrulaması PR üzerinde takip edilecek.
**Kapsam dosyası:** `src/tests/finality_live_path.rs`

> Bu belge harici audit için operasyonel kanıttır. `finality_adversarial.rs`
> byzantine/split-brain/equivocation senaryolarını kapsarken, bu son tarama
> canlı finality penceresindeki “dürüst yol” ve sınır koşullarına odaklanır.

## Test kapsamı

| Test | Risk | Beklenen güvenlik davranışı |
|------|------|-----------------------------|
| `live_path_epoch_change_isolates_votes` | Eski epoch oylarının yeni pencereye sızması | Her epoch kendi `FinalityAggregator` penceresinde izole kalır. |
| `live_path_prevote_with_wrong_height_rejected` | Geç/yanlış height prevote kabulü | Aggregator’ın checkpoint height/hash bağlamı dışındaki imza reddedilir. |
| `live_path_double_sign_window_is_tight` | Aynı validator’ın aynı epoch içinde birden görevla oy saydırması | İlk oy sayılır; duplicate reddedilir; çelişkili hash evidence üretir. |
| `live_path_snapshot_hash_distinguishes_sets` | Validator set snapshot hash çakışması/regresyonu | Farklı set boyutu veya stake farklı hash üretir; aynı set deterministiktir. |

## Doğrulama komutları

```bash
cargo test --lib finality_live_path -- --nocapture
cargo test --lib finality_adversarial -- --nocapture
cargo clippy --lib --tests -- -D warnings
cargo fmt --all -- --check
```

Bu sandbox oturumunda `cargo`/`rustc` binary’si bulunmadığı için komutlar yerelde
çalıştırılamadı; PR açıldıktan sonra GitHub Actions `Budlum Core` işi bu testleri
`cargo test --lib --verbose` altında koşturacaktır.

## Kabul kriteri

- [x] `src/tests/finality_live_path.rs` repo içinde mevcut.
- [x] `src/tests/mod.rs` içinde `pub mod finality_live_path;` aktif.
- [x] Testler gerçek BLS anahtar/imza helper’larını kullanır (`sign_bls`, PoP).
- [x] Test kapsamı finality pencere izolasyonu, height mismatch, duplicate vote ve snapshot hash ayrımı risklerini kapsar.
- [ ] CI `Budlum Core` yeşil.

## Sınırlar

- Bu tarama yeni finality algoritması eklemez; sadece canlı yol regresyonlarını yakalar.
- Quorum split-brain ve invalid-signature rate-limit senaryoları `src/tests/finality_adversarial.rs` kapsamındadır.
- PoA izolasyonu ve storage finality adapter doğrulamaları kendi testlerinde takip edilir.
