# aggregation

Yeni kodun (`src/aggregation/`, PR #188) bulguları:

- B-0006: referans backend yalnız feature kapısıyla dışlanıyor, çalışma zamanı savunması yok.
- B-0007: şema kimlikleri yer tutucu (0x0101 ...).
- B-0008: `AggPool::per_sender` yalnız `expire_orphans` çağrıldığında budanıyor.

Detay: `audit-notes/report.md`, bolum 2.

## Tur 2

B-0015: #188 kapatıldı, stack uygulaması esas. B-0017: stack `claims_root` doğrulandı (tanıtma + yaprak/düğüm ayrımı). Ayrıntı: `round2.md`.
