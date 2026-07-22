# Bench Baseline — Task 8.12 (çatı, dürüst marker'lı)

> **TR Özet:** Bu belge bench baseline altyapısının çatısıdır (Dalga 8).
> İlk SAYISAL tablo CI artifact'lerinden alınıp **Dalga 9'da** bu dosyaya
# mühürlenecek — o güne kadar sayı beklemeyin, bu bilinçli bir borçtur (marker).

## Mevcut bench envanteri

micro
single_node

## Nasıl koşulur

- `cargo bench --bench timing_safe` — 8.6 Timing-Safe Regression job'u her push'ta koşturur (dudect-tarzı istatistiksel zamanlama).
- CI artifact akışı: bench çıktıları Dalga 8 sonrası artifact olarak saklanır; baseline tablosu oradan türetilir.

## Ratchet kuralı

Coverage ratchet ile aynı ilke: baseline yalnız bilinçli PR ile güncellenir;
regresyon tespitinde rapor cuplaji CI job log'u + bu dosyadaki MÜHÜRLÜ sayılar.
