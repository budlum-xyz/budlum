# İşletim Sistemi Denetimi: Ubuntu 24.04 LTS (Noble) x86_64

## 1. Ortam Bilgileri
- **Mimari**: `x86_64`
- **Çekirdek**: Linux 6.8 GNU/Linux
- **Dağıtım**: Ubuntu 24.04 LTS (Noble Numbat)
- **Rolü**: GitHub Actions standart CI runner (`ubuntu-latest` / `ubuntu-24.04`) ve Docker smoke konteynerleri.

## 2. Test ve Çalıştırma Sonuçları
- `actionlint`, `hadolint`, `cargo-vet`, `zizmor`: Başarılı.
- Determinism testleri: İki farklı Ubuntu runner'da üretilen ikili (binary) hash değerlerinin birebir eşleştiği doğrulandı.
- `cargo test --lib`: Başarılı.

## 3. Bulgular ve Çözümler
- **B-OS-UBU-01 (glibc 2.39 Uyumluluğu ve Pthread Kilitleri)**:
  - *Belirti*: Ubuntu 24.04 glibc 2.39 üzerinde pthread kilitleme zaman aşımlarında zamanlama hassasiyet farkı.
  - *Kök Neden*: `wall_clock_locks.rs` testinin nanosaniye düzeyinde tolerans aralığının dar tutulması.
  - *Çözüm*: Kilit zamanlama toleransı monotonic clock ile yeniden kalibre edildi.
  - *Durum*: Çözüldü (`ad88285c`).
