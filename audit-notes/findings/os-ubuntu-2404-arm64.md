# İşletim Sistemi Denetimi: Ubuntu 24.04 ARM64 (aarch64)

## 1. Ortam Bilgileri
- **Mimari**: `aarch64` (ARMv8-A / ARMv9-A)
- **Rolü**: Çapraz mimari determinizm (`ubuntu-24.04-arm`), AWS Graviton ve Apple Silicon hedef doğrulaması.

## 2. Test ve Çalıştırma Sonuçları
- `Cross-arch determinism (ubuntu-24.04-arm)` CI iş akışı.
- Endianness ve bellek hizalama kontrolleri.

## 3. Bulgular ve Çözümler
- **B-OS-ARM-01 (Atomic Yükleme ve Hizalama Sınırları)**:
  - *Belirti*: ARM64 mimarisinde 128-bit atomik işlemler (`AtomicU128`) x86_64'e göre katı 16-byte hizalama talep eder.
  - *Kök Neden*: Ham byte dizilerinden dönüştürülen bazı durum sayaçlarının hizalanmamış bellek adresinden okunması (`misaligned pointer dereference`).
  - *Çözüm*: `read_unaligned` ve güvenli sarmalayıcılar (`bytemuck::Pod`) kullanılarak x86 ve ARM64 arasında hizalama bağımsızlığı sağlandı.
  - *Durum*: Çözüldü (`ad88285c`).
