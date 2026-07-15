# ConsensusStateV2 Migration İskeleti (ADIM 2 §1.4)

**Tarih:** 2026-07-15  
**Durum:** Minimum migration hook + offline gate mevcut; canlı state transform yok.  
**Kod:** `src/chain/snapshot.rs`, `src/main.rs`, `src/cli/commands.rs`

> Amaç: mainnet öncesi state şema geçişlerinin “sessizce kabul” yerine
> fail-closed, backup-zorunlu ve audit edilebilir bir kapıdan geçmesini sağlamak.

## Sürüm penceresi

`src/chain/snapshot.rs::StateSnapshotV2::from_bytes()` içinde desteklenen schema
penceresi fail-closed kontrol edilir:

| Pencere | Davranış |
|---------|----------|
| `schema_version < 2` | Legacy snapshot reddedilir; ara release ile restore gerekir. |
| `schema_version = 2 veya 3` | Kabul edilir; `#[serde(default)]` alanlarıyla geriye uyum korunur. |
| `schema_version > 3` | Future snapshot reddedilir; downgrade/yanlış binary riski engellenir. |

## Kod iskeleti

`StateSnapshotV2::from_bytes()` şu an minimum migration hook görevi görür:
unsupported legacy/future şemaları reddeder, schema-2/3 snapshot’ları deserialize
eder. ADIM 2 kapsamı bunu operasyon dokümanı ve offline CLI preflight ile
sabitlemek; gelecekteki `v3 -> v4` gibi gerçek transform fonksiyonları bu alana
explicit olarak eklenecektir.

## Offline CLI kapısı

`src/cli/commands.rs` içinde:

```bash
budlum-core --migrate-v2 ./data/node.db --backup-dir ./data/backups
```

akışı tanımlıdır. `src/main.rs` bu modda:

1. hedef sled DB’yi açar,
2. migration öncesi atomik ve doğrulanmış backup üretir,
3. desteklenen schema penceresini raporlar,
4. canlı node başlatmadan çıkar.

Bu ADIM 2 iskeleti **veri transformasyonu yapmaz**; sadece preflight + backup +
fail-closed policy sağlar. Gerçek çok-adımlı migration gerekirse bu hook’a
explicit `v2 -> v3 -> v4` transform fonksiyonları eklenecek.

## Test kapsamı

`src/chain/snapshot.rs::tests::test_snapshot_v2_migration_hook_rejects_unsupported_versions`
şunları doğrular:

- `schema_version = 1` reddedilir,
- `schema_version = 99` reddedilir,
- `schema_version = 2` desteklenir,
- güncel schema (`3`) desteklenir.

## Doğrulama komutları

```bash
cargo test --lib snapshot_v2_migration_hook -- --nocapture
cargo test --lib persistence -- --nocapture
cargo test --lib --verbose
```

Bu sandbox oturumunda `cargo`/`rustc` binary’si bulunmadığı için komutlar yerelde
çalıştırılamadı; PR CI sonucu zorunlu kanıt olarak izlenecektir.

## Kabul kriteri

- [x] Desteklenen schema penceresi `StateSnapshotV2::from_bytes()` içinde fail-closed tanımlı.
- [x] Unsupported legacy/future snapshot fail-closed.
- [x] Offline migration CLI preflight + zorunlu backup mevcut.
- [x] Offline migration preflight audit edilebilir CLI çıktısı üretiyor.
- [x] Test iskeleti legacy/future/current yollarını kapsıyor; schema-2 geriye uyum persistence testlerinde korunuyor.
- [ ] CI `Budlum Core` yeşil.

## Bilinçli sınırlar

- Canlı zincirde otomatik state rewrite yok.
- Unknown future schema için “best effort” deserialize yok.
- Backup alınmadan migration kapısı başarı raporu vermez.
