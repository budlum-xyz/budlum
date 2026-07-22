# Dependency Audit Raporu ()

**Güncelleme:** 2026-07-15
**Araç:** `cargo-audit` (https://github.com/rustsec/rustsec)
**Repo:** `lubosruler/budlum`
**Durum:** Tooling hazır; bu sandbox oturumunda Rust toolchain (`cargo`/`rustc`) bulunmadığı için audit komutu yerelde koşturulamadı.

> Bu dosya harici audit/supply-chain teslim paketinin parçasıdır. “Bilinen CVE yok”
> iddiası ancak yetkili ortamda `./scripts/audit-deps.sh` başarıyla çalıştırıldıktan
> ve çıktı bu dosyaya işlendiğinde yapılabilir.

## Çalıştırma

```bash
./scripts/audit-deps.sh
```

Script davranışı:

1. `cargo-audit` yoksa `cargo install --locked cargo-audit` ile kurmayı dener.
2. `Cargo.lock` üzerinde RustSec advisory taraması yapar.
3. Bu raporu günceller.
4. Audit exit code’unu CI/release ortamına geri döndürür.

## Son doğrulama notları

Aktif lockfile üzerinde offline gözlem:

| Crate | Aktif sürüm | Önceki bulguya göre durum |
|-------|-------------|---------------------------|
| `crossbeam-epoch` | `0.9.20` | Önceki `>=0.9.20` önerisi karşılanmış görünüyor. |
| `protobuf` | `3.7.2` | Önceki `>=3.7.2` önerisi karşılanmış görünüyor. |
| `quinn-proto` | `0.11.16` | Önceki `>=0.11.15` önerisi karşılanmış görünüyor. |
| `hickory-proto` | `0.24.4` | RustSec durumunun yetkili `cargo audit` ile yeniden kontrolü gerekir. |
| `ring` | `0.16.20` ve `0.17.14` | Eski `ring` transitive bağımlılığı için risk kabulü/upgrade yolu kontrol edilmeli. |
| `rustls-webpki` | `0.101.7` ve `0.103.13` | Eski transitive sürüm için risk kabulü/upgrade yolu kontrol edilmeli. |

Bu tablo `cargo audit` yerine geçmez; sadece lockfile’dan okunabilen sürüm
kanıtıdır.

## Kabul kriteri

- [x] `scripts/audit-deps.sh` mevcut ve rapor üretmek üzere tasarlı.
- [x] `Cargo.lock` dependency sürümleri görünür.
- [ ] Yetkili Rust ortamında `./scripts/audit-deps.sh` çalıştırıldı.
- [ ] Çıktıdaki CVE/advisory listesi bu rapora işlendi.
- [ ] High/critical bulgular için upgrade veya yazılı risk kabulü var.

## Harici audit’e teslim edilecekler

```bash
git rev-parse HEAD
cargo tree > cargo-tree.txt
cargo metadata --format-version=1 > cargo-metadata.json
./scripts/audit-deps.sh
./scripts/generate-sbom.sh
```

Üretilen `cargo-tree.txt`, `cargo-metadata.json`, `docs/operations/DEPENDENCY_AUDIT.md`
ve `sbom.cdx.json` audit paketine eklenmelidir.
