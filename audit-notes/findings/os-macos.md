# İşletim Sistemi Denetimi: macOS (Apple Darwin x86_64 & aarch64)

## 1. Ortam Bilgileri
- **İşletim Sistemi**: macOS Sonoma / Sequoia (`macos-latest`)
- **Derleyici**: Apple Clang + LLVM 19 + Rust
- **Rolü**: Geliştirici iş istasyonları ve CI çoklu platform derleme doğrulaması.

## 2. Test ve Çalıştırma Sonuçları
- Mach-O ikili derleme ve linkleme.
- POSIX soket ve `kqueue` tabanlı asenkron ağ döngüsü kontrolleri.

## 3. Bulgular ve Çözümler
- **B-OS-MAC-01 (Kqueue ve Epoll Eşdeğerliği Zaman Aşımı Davranışı)**:
  - *Belirti*: P2P ağ testlerinde `tokio` zaman aşımlarında Darwin kqueue üzerinde kilit açılma milisaniye gecikmeleri.
  - *Kök Neden*: macOS çekirdeğinin timer coalescing politikası nedeniyle gevşek zaman aşımı bildirimleri.
  - *Çözüm*: P2P ağ testlerindeki eşzamanlılık kilitleri toleranslı delta süreleriyle (`Duration::from_millis(50)`) korundu.
  - *Durum*: Çözüldü (`ad88285c`).
