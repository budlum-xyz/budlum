# BNS — Budlum Name Service (`.bud`) (modül README'si)

**Bu dosya, Task 10 Bölüm 4 modül-ayrımı kuralı gereği BNS'in kendi README'sidir.**

## Durum

- **Olgunluk:** iskelet mevcut — `src/bns/` (`registry.rs`: `BnsRegistry`,
  `types.rs`: `NameRecord`/`BnsError`/`BnsResolved`).
- **Düzeltme (2026-07-18 kod doğrulaması):** Task 10 dokümanın Bölüm 4.3'teki
  "henüz mimarisi yok, sıfırdan" ifadesi güncel değildir — kayıt/resolve/transfer/
  renewal/subdomain/maliyet-ölçekleme davranışları kodlu ve testlidir.
- **Kapsam dışı (bu tur):** squatting/speaking-rights ekonomisi, B.U.D./AI layer
  entegrasyon sözleşmesi — Task 10 dokümanı §4.4 gereği ayrı talimat turu.

## Mevcut davranış (test-kilitli)

Kayıt + resolve, süre sonu (expiration), yenileme (renewal), yalnız-sahip
subdomain, geçersiz-ad reddi, devir (transfer), storage ile full-resolve,
maliyet ölçekleme (cost scaling).

## Test suite

- 9 test, hepsi `test_bns_` prefix'li: `src/tests/bns.rs` (2),
  `src/tests/bns_expanded.rs` (7).
- Şu an Core lib suite içinde (`cargo test --lib`) koşar — **bu sprint (P10
  Bölüm 4) kapsamında ayrı isim-kanaryalı CI gate'i ekleniyor**
  (`scripts/check-bns-gate.sh`, B.U.D. kapı deseni kopyası; vacuous-gate korumalı).
